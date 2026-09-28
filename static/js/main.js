document.addEventListener('DOMContentLoaded', () => {
    const realtimeStatus = document.querySelector('[data-realtime-status]');
    const realtimeLabel = realtimeStatus?.querySelector('[data-realtime-status-label]');
    const realtimeDetail = realtimeStatus?.querySelector('[data-realtime-status-detail]');
    const realtime = {
        socket: null,
        seen: new Set(),
        auditSeen: new Set(),
        sequence: Number(sessionStorage.getItem('taskhq:last-event-sequence') || 0),
        auditSequence: Number(sessionStorage.getItem('taskhq:last-audit-log-id') || 0),
        setStatus(status, label, detail) {
            if (!realtimeStatus) return;
            realtimeStatus.dataset.realtimeStatus = status;
            if (realtimeLabel) realtimeLabel.textContent = label;
            if (realtimeDetail) realtimeDetail.textContent = detail;
        },
        handleEvent(event) {
            if (!event?.eventId || realtime.seen.has(event.eventId)) return;
            realtime.seen.add(event.eventId);
            realtime.sequence = Math.max(realtime.sequence, Number(event.sequence || 0));
            sessionStorage.setItem('taskhq:last-event-sequence', String(realtime.sequence));
            window.dispatchEvent(new CustomEvent('taskhq:realtime', { detail: event }));
            if (event.eventType === 'NOTIFICATION_CREATED' || event.entityType === 'notification') {
                document.dispatchEvent(new Event('taskhq:refresh-notifications'));
            }
        },
        handleAuditEvent(event) {
            if (!event?.eventId || realtime.auditSeen.has(event.eventId)) return;
            realtime.auditSeen.add(event.eventId);
            realtime.auditSequence = Math.max(realtime.auditSequence, Number(event.sequence || 0));
            sessionStorage.setItem('taskhq:last-audit-log-id', String(realtime.auditSequence));
            window.dispatchEvent(new CustomEvent('taskhq:audit-log', { detail: event }));
        },
        async connect() {
            if (!window.io || !realtimeStatus) return;
            try {
                const response = await fetch('/api/realtime/token', { credentials: 'same-origin', cache: 'no-store' });
                if (!response.ok) return;
                const { token } = await response.json();
                realtime.socket = window.io({ auth: { token }, transports: ['websocket', 'polling'], reconnection: true });
                realtime.socket.on('connect', () => {
                    realtime.setStatus('online', 'Live', 'Connected securely');
                    realtime.socket.emit('sync', { lastEventId: realtime.sequence }, (result) => {
                        if (result?.ok) result.events.forEach((event) => realtime.handleEvent(event));
                    });
                    if (document.querySelector('[data-audit-stream]')) {
                        realtime.socket.emit('audit_sync', { lastAuditLogId: realtime.auditSequence }, (result) => {
                            if (!result?.ok) return;
                            result.events.forEach((event) => realtime.handleAuditEvent(event));
                            realtime.auditSequence = Math.max(realtime.auditSequence, Number(result.lastAuditLogId || 0));
                            sessionStorage.setItem('taskhq:last-audit-log-id', String(realtime.auditSequence));
                        });
                    }
                    const taskMatch = window.location.pathname.match(/\/tasks\/(\d+)\/view/);
                    const teamMatch = window.location.pathname.match(/\/teams\/(\d+)$/);
                    if (taskMatch) realtime.socket.emit('join_room', { room: `task:${taskMatch[1]}` });
                    if (teamMatch) realtime.socket.emit('join_room', { room: `team:${teamMatch[1]}` });
                });
                realtime.socket.on('reconnect_attempt', () => realtime.setStatus('reconnecting', 'Reconnecting...', 'Restoring live updates'));
                realtime.socket.on('disconnect', () => realtime.setStatus('offline', 'Offline', 'Live updates paused'));
                realtime.socket.on('connect_error', () => realtime.setStatus('reconnecting', 'Reconnecting...', 'Retrying secure connection'));
                realtime.socket.on('realtime_event', (event) => realtime.handleEvent(event));
                realtime.socket.on('audit_log_event', (event) => realtime.handleAuditEvent(event));
                realtime.socket.on('presence', (event) => window.dispatchEvent(new CustomEvent('taskhq:presence', { detail: event })));
                window.setInterval(() => realtime.socket?.connected && realtime.socket.emit('heartbeat'), 25000);
            } catch (error) {
                realtime.setStatus('offline', 'Offline', 'Live updates unavailable');
                console.error('Realtime connection failed', error);
            }
        },
        async loadPermissions() {
            try {
                const response = await fetch('/api/me/permissions', { credentials: 'same-origin', cache: 'no-store' });
                if (!response.ok) return;
                const result = await response.json();
                const allowed = new Set(result.permissions.map((permission) => permission.key));
                document.querySelectorAll('[data-permission]').forEach((element) => {
                    const permission = element.dataset.permission;
                    const action = permission.split('.').pop();
                    const scoped = action === 'edit' || action === 'delete' || action === 'assign';
                    element.hidden = !allowed.has(permission) && !(scoped && (allowed.has(`${permission}_own`) || allowed.has(`${permission}_any`)));
                });
            } catch (error) {
                console.error('Could not load permissions', error);
            }
        },
    };
    window.TaskHQRealtime = realtime;
    realtime.connect();
    realtime.loadPermissions();

    window.addEventListener('taskhq:realtime', ({ detail: event }) => {
        if (event.entityType === 'task' && event.entityId) {
            const taskId = String(event.entityId);
            const row = document.querySelector(`[data-task-id="${taskId}"]`);
            const status = event.payload?.newStatus;
            if (row && status) {
                row.dataset.taskStatus = status;
                row.querySelector('[data-realtime-task-status]')?.replaceChildren(document.createTextNode(status));
            }
            if (event.eventType === 'TASK_DELETED') row?.remove();
        }

        if (event.eventType === 'PERMISSIONS_UPDATED' && Number(event.entityId) === Number(document.body.dataset.userId)) {
            realtime.loadPermissions();
        }

        if (event.eventType === 'COMMENT_CREATED' && event.entityType === 'team') {
            const messageList = document.querySelector('[data-team-chat-messages]');
            const messageId = String(event.payload?.messageId || '');
            if (!messageList || messageList.querySelector(`[data-team-chat-message-id="${messageId}"]`)) return;
            document.querySelector('#team-chat-empty')?.remove();
            const message = document.createElement('div');
            message.dataset.teamChatMessage = '';
            message.dataset.teamChatMessageId = messageId;
            message.style.cssText = 'padding:14px 16px; border:1px solid #edf2f7; border-radius:12px; background:#fbfdff;';
            const header = document.createElement('div');
            header.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:8px;';
            const author = document.createElement('strong');
            author.style.cssText = 'font-size:13px;';
            author.textContent = event.payload?.username || 'User';
            const timestamp = document.createElement('small');
            timestamp.style.cssText = 'color:var(--muted); font-size:10px;';
            timestamp.textContent = event.timestamp || '';
            header.append(author, timestamp);
            const body = document.createElement('p');
            body.style.cssText = 'margin:0; color:var(--ink); line-height:1.6;';
            body.textContent = event.payload?.body || '';
            message.append(header, body);
            messageList.append(message);
        }
    });

    const auditStream = document.querySelector('[data-audit-stream]');
    const auditRows = auditStream?.querySelector('[data-audit-rows]');
    const auditCounter = document.querySelector('[data-audit-count]');
    const auditLiveInsert = auditStream?.dataset.auditLiveInsert === 'true';
    const auditRowLimit = Number(auditStream?.dataset.auditRowLimit || 0);
    const auditHasPageNav = auditStream?.dataset.auditHasNav === 'true';
    const auditDetailBase = auditStream?.dataset.auditDetailBase || '';
    const auditRowIds = () => [...(auditRows?.querySelectorAll('tr[data-audit-log-id]') || [])];

    const auditCell = (className, text) => {
        const cell = document.createElement('td');
        if (className) cell.className = className;
        cell.textContent = text;
        return cell;
    };

    const buildAuditRow = (event) => {
        const row = document.createElement('tr');
        row.dataset.auditLogId = String(event.sequence);
        row.append(auditCell('muted-cell', event.timestamp || ''));
        row.append(auditCell('', event.actorName || 'System'));
        row.append(auditCell('strong-cell', event.action || ''));

        const resultCell = document.createElement('td');
        const result = String(event.result || '');
        const badge = document.createElement('span');
        badge.className = 'status-badge status-neutral';
        badge.textContent = result.charAt(0).toUpperCase() + result.slice(1);
        resultCell.append(badge);
        row.append(resultCell);

        row.append(auditCell('', event.entityType || '-'));
        row.append(auditCell('', event.entityId ? `#${event.entityId}` : '-'));
        row.append(auditCell('', event.ipAddress || '-'));

        const details = document.createElement('td');
        details.className = 'muted-cell';
        const summary = document.createElement('div');
        summary.textContent = event.message || `${event.actorName || 'System'} ${event.action || ''} ${event.entityType || ''}`.trim();
        details.append(summary);
        (event.changes || []).slice(0, 3).forEach((change) => {
            const line = document.createElement('div');
            const caption = document.createElement('strong');
            caption.textContent = `${change.field}: `;
            const before = change.before === null || change.before === undefined ? '-' : String(change.before);
            const after = change.after === null || change.after === undefined ? '-' : String(change.after);
            line.append(caption, document.createTextNode(`${before} → ${after}`));
            details.append(line);
        });
        if (!event.changes || !event.changes.length) {
            const empty = document.createElement('div');
            empty.textContent = '-';
            details.append(empty);
        }
        const detailLink = document.createElement('a');
        detailLink.href = `${auditDetailBase}/${event.sequence}`;
        detailLink.textContent = 'View details';
        details.append(detailLink);
        row.append(details);
        return row;
    };

    const bumpAuditCounter = () => {
        if (!auditCounter) return;
        const parts = auditCounter.textContent.trim().split(/\s+/);
        const range = (parts[1] || '').split('-');
        if (range.length !== 2) return;
        const first = Number(range[0]);
        const last = Number(range[1]);
        const total = Number(parts[3]);
        if (!Number.isFinite(last) || !Number.isFinite(total)) return;
        if (first === 0 && last === 0) {
            auditCounter.textContent = 'Showing 1-1 of 1';
            return;
        }
        if (first !== 1) return;
        const nextLast = auditRowLimit ? Math.min(last + 1, auditRowLimit) : last + 1;
        auditCounter.textContent = `Showing ${first}-${nextLast} of ${total + 1}`;
    };

    window.addEventListener('taskhq:audit-log', ({ detail: event }) => {
        const showNotice = () => {
            const notice = document.querySelector('[data-audit-live-notice]');
            if (notice) notice.hidden = false;
        };
        const rowId = String(event?.sequence ?? '');
        if (!auditRows || !auditLiveInsert || !rowId) {
            showNotice();
            return;
        }
        const rendered = auditRowIds();
        if (rendered.some((row) => row.dataset.auditLogId === rowId)) return;
        // Replayed history (audit_sync after a fresh tab) is older than the
        // rendered page; inserting it would push the newest rows out.
        const maxRenderedId = rendered.reduce((max, row) => Math.max(max, Number(row.dataset.auditLogId) || 0), 0);
        if (Number(rowId) <= maxRenderedId) return;
        if (auditRowLimit && !auditHasPageNav && rendered.length >= auditRowLimit) {
            showNotice();
            return;
        }
        if (auditRowLimit) {
            let rows = auditRowIds();
            while (rows.length >= auditRowLimit) {
                rows[rows.length - 1].remove();
                rows = auditRowIds();
            }
        }
        auditRows.querySelector('.empty-state')?.closest('tr')?.remove();
        auditRows.prepend(buildAuditRow(event));
        bumpAuditCounter();
    });
    document.querySelector('[data-audit-refresh]')?.addEventListener('click', () => window.location.reload());

    document.querySelectorAll('[data-password-toggle]').forEach((button) => {
        button.addEventListener('click', () => {
            const input = document.getElementById(button.dataset.passwordToggle);
            if (!input) return;
            const visible = input.type === 'text';
            input.type = visible ? 'password' : 'text';
            button.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
            button.setAttribute('title', visible ? 'Show password' : 'Hide password');
            button.classList.toggle('is-visible', !visible);
        });
    });

    const loginForm = document.querySelector('form.auth-form');
    if (loginForm) {
        const clearVisibleLoginFields = () => {
            loginForm.querySelector('[name="login_username"]')?.setAttribute('value', '');
            loginForm.querySelector('[name="login_password"]')?.setAttribute('value', '');
            loginForm.querySelector('[name="login_username"]').value = '';
            loginForm.querySelector('[name="login_password"]').value = '';
        };
        clearVisibleLoginFields();
        window.setTimeout(clearVisibleLoginFields, 120);
        window.addEventListener('pageshow', clearVisibleLoginFields);
    }

    document.querySelectorAll('.flash-message').forEach((message) => {
        const dismiss = () => {
            message.classList.add('is-dismissing');
            window.setTimeout(() => {
                const stack = message.closest('.flash-stack');
                message.remove();
                if (stack && !stack.querySelector('.flash-message')) {
                    stack.closest('.flash-region')?.remove();
                }
            }, 220);
        };
        message.querySelector('.flash-close')?.addEventListener('click', dismiss);
        window.setTimeout(dismiss, 6000);
    });

    const notificationWrap = document.querySelector('.notification-wrap[data-notifications-feed]');
    if (notificationWrap) {
        const notificationItems = notificationWrap.querySelector('[data-notification-items]');
        let renderedNotifications = '';

        const refreshNotifications = async () => {
            if (document.hidden) return;
            try {
                const response = await fetch(notificationWrap.dataset.notificationsFeed, {
                    headers: { Accept: 'application/json' },
                    credentials: 'same-origin',
                    cache: 'no-store',
                });
                if (!response.ok) return;
                const result = await response.json();
                const component = window.Alpine?.$data(notificationWrap);
                if (component) component.unread = result.unread_count;

                const signature = JSON.stringify(result.notifications);
                if (signature === renderedNotifications) return;
                renderedNotifications = signature;
                notificationItems.replaceChildren();

                if (!result.notifications.length) {
                    const empty = document.createElement('div');
                    empty.className = 'empty-mini';
                    empty.textContent = 'You are all caught up.';
                    notificationItems.append(empty);
                    return;
                }

                result.notifications.forEach((item) => {
                    const link = document.createElement('a');
                    link.href = item.url;
                    link.className = 'notification-item';
                    link.dataset.notificationId = item.id;
                    const icon = document.createElement('span');
                    icon.className = 'notification-icon';
                    icon.setAttribute('aria-hidden', 'true');
                    icon.textContent = '•';
                    const content = document.createElement('span');
                    const message = document.createElement('strong');
                    message.textContent = item.message;
                    const createdAt = document.createElement('small');
                    createdAt.textContent = item.created_at;
                    content.append(message, createdAt);
                    const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                    arrow.setAttribute('viewBox', '0 0 24 24');
                    arrow.setAttribute('fill', 'none');
                    arrow.setAttribute('stroke', 'currentColor');
                    arrow.setAttribute('stroke-width', '1.8');
                    arrow.setAttribute('aria-hidden', 'true');
                    arrow.classList.add('notification-arrow');
                    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                    path.setAttribute('d', 'm9 18 6-6-6-6');
                    arrow.append(path);
                    link.append(icon, content, arrow);
                    notificationItems.append(link);
                });
            } catch (error) {
                console.error('Could not refresh notifications', error);
            }
        };

        refreshNotifications();
        window.setInterval(refreshNotifications, 5000);
        document.addEventListener('visibilitychange', refreshNotifications);
        document.addEventListener('taskhq:refresh-notifications', refreshNotifications);
    }

    document.querySelectorAll('[data-confirm]').forEach((form) => {
        form.addEventListener('submit', (event) => {
            if (!window.confirm(form.dataset.confirm)) event.preventDefault();
        });
    });

    document.querySelectorAll('[data-select-group]').forEach((button) => {
        button.addEventListener('click', () => {
            const form = button.closest('[data-role-form]');
            form?.querySelectorAll(`[data-permission-group="${button.dataset.selectGroup}"]`).forEach((checkbox) => {
                checkbox.checked = true;
            });
        });
    });

    const teamChatForm = document.querySelector('[data-team-chat-form]');
    if (teamChatForm) {
        const messageInput = teamChatForm.querySelector('[name="message"]');
        const messageList = document.querySelector('[data-team-chat-messages]');
        const submitButton = teamChatForm.querySelector('[type="submit"]');
        const status = document.createElement('p');
        status.setAttribute('role', 'status');
        status.setAttribute('aria-live', 'polite');
        status.className = 'text-sm text-slate-600';
        teamChatForm.append(status);

        teamChatForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            if (!messageInput.value.trim() || submitButton.disabled) return;

            submitButton.disabled = true;
            status.textContent = 'Sending...';
            try {
                const response = await fetch(teamChatForm.action || window.location.href, {
                    method: 'POST',
                    body: new FormData(teamChatForm),
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin',
                });
                const result = await response.json();
                if (!response.ok || !result.ok) throw new Error(result.error || 'Message could not be sent.');

                document.querySelector('#team-chat-empty')?.remove();
                const message = document.createElement('div');
                message.dataset.teamChatMessage = '';
                message.dataset.teamChatMessageId = String(result.message.id);
                message.style.cssText = 'padding:14px 16px; border:1px solid #edf2f7; border-radius:12px; background:#fbfdff;';
                const header = document.createElement('div');
                header.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:8px;';
                const author = document.createElement('strong');
                author.style.cssText = 'font-size:13px;';
                author.textContent = result.message.username;
                const timestamp = document.createElement('small');
                timestamp.style.cssText = 'color:var(--muted); font-size:10px;';
                timestamp.textContent = result.message.created_at;
                header.append(author, timestamp);
                const body = document.createElement('p');
                body.style.cssText = 'margin:0; color:var(--ink); line-height:1.6;';
                body.textContent = result.message.body;
                message.append(header, body);
                messageList.append(message);

                messageInput.value = '';
                messageInput.focus({ preventScroll: true });
                status.textContent = 'Message sent.';
            } catch (error) {
                status.textContent = error.message;
            } finally {
                submitButton.disabled = false;
            }
        });
    }

    const teamMemberForm = document.querySelector('[data-team-member-form]');
    if (teamMemberForm) {
        const userIdsInput = teamMemberForm.querySelector('[name="user_ids"]');
        const submitButton = teamMemberForm.querySelector('[type="submit"]');
        const status = document.querySelector('[data-team-member-status]');
        const memberList = document.querySelector('[data-team-members]');
        const count = document.querySelector('[data-team-member-count]');

        teamMemberForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            if (submitButton.disabled) return;

            submitButton.disabled = true;
            status.hidden = false;
            status.style.color = 'var(--muted)';
            status.textContent = 'Adding members...';
            userIdsInput.removeAttribute('aria-invalid');
            try {
                const response = await fetch(teamMemberForm.getAttribute('action') || window.location.href, {
                    method: 'POST',
                    body: new FormData(teamMemberForm),
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin',
                });
                const result = await response.json();
                if (!response.ok || !result.ok) throw new Error(result.error || 'Members could not be added.');

                document.querySelector('#team-members-empty')?.remove();
                result.members.forEach((member) => {
                    const row = document.createElement('div');
                    row.dataset.teamMember = '';
                    row.dataset.memberId = member.id;
                    row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:10px; padding:10px 12px; border:1px solid #edf2f7; border-radius:10px; background:#f8fafc;';

                    const identity = document.createElement('div');
                    identity.style.cssText = 'display:flex; align-items:center; gap:10px; min-width:0;';
                    const avatar = document.createElement('span');
                    avatar.className = 'avatar';
                    avatar.style.cssText = 'width:32px; height:32px; font-size:12px;';
                    avatar.textContent = member.username.slice(0, 1).toUpperCase();
                    const details = document.createElement('div');
                    const username = document.createElement('strong');
                    username.style.cssText = 'display:block; font-size:11px;';
                    username.textContent = member.username;
                    const metadata = document.createElement('small');
                    metadata.style.cssText = 'display:block; color:var(--muted); font-size:10px;';
                    metadata.textContent = `ID ${member.id} · ${member.role || 'User'}`;
                    details.append(username, metadata);
                    identity.append(avatar, details);
                    row.append(identity);

                    const active = document.createElement('span');
                    active.className = 'status-badge status-neutral';
                    active.textContent = 'Active';
                    row.append(active);

                    const canManageMembers = memberList.dataset.canManageMembers === 'true';
                    const isLeader = Number(memberList.dataset.leaderId) === member.id;
                    if (canManageMembers && !isLeader) {
                        const removeForm = document.createElement('form');
                        removeForm.method = 'POST';
                        removeForm.onsubmit = () => window.confirm('Remove this team member?');
                        const csrf = teamMemberForm.querySelector('[name="csrf_token"]').cloneNode();
                        const action = document.createElement('input');
                        action.type = 'hidden';
                        action.name = 'action';
                        action.value = 'remove_member';
                        const memberId = document.createElement('input');
                        memberId.type = 'hidden';
                        memberId.name = 'member_id';
                        memberId.value = member.id;
                        const removeButton = document.createElement('button');
                        removeButton.className = 'logout-link';
                        removeButton.type = 'submit';
                        removeButton.textContent = 'Remove';
                        removeForm.append(csrf, action, memberId, removeButton);
                        row.append(removeForm);
                    }
                    memberList.append(row);
                });

                count.textContent = memberList.querySelectorAll('[data-team-member]').length;
                userIdsInput.value = '';
                userIdsInput.focus({ preventScroll: true });
                status.style.color = '#166534';
                status.textContent = `Added ${result.members.length} team member(s).`;
            } catch (error) {
                status.style.color = '#b91c1c';
                status.textContent = error.message;
                userIdsInput.setAttribute('aria-invalid', 'true');
                userIdsInput.focus({ preventScroll: true });
            } finally {
                submitButton.disabled = false;
            }
        });
    }

    document.querySelectorAll('[data-assistant-prompt]').forEach((button) => {
        button.addEventListener('click', () => {
            const assistantForm = document.querySelector('[data-assistant-form]');
            const promptInput = assistantForm?.querySelector('[name="prompt"]');
            if (!promptInput) return;
            promptInput.value = button.dataset.assistantPrompt;
            promptInput.focus();
        });
    });

    const assistantForm = document.querySelector('[data-assistant-form]');
    if (assistantForm) {
        const promptInput = assistantForm.querySelector('[name="prompt"]');
        const submitButton = assistantForm.querySelector('[type="submit"]');
        const submitLabel = assistantForm.querySelector('[data-assistant-submit-label]');
        const status = assistantForm.querySelector('[data-assistant-status]');
        const conversation = document.querySelector('[data-assistant-conversation]');

        assistantForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const prompt = promptInput.value.trim();
            if (!prompt || submitButton.disabled) return;

            submitButton.disabled = true;
            submitLabel.textContent = 'Thinking...';
            status.textContent = 'Checking your visible tasks...';
            try {
                const csrfToken = assistantForm.querySelector('[name="csrf_token"]').value;
                const response = await fetch(assistantForm.dataset.askUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken,
                    },
                    body: JSON.stringify({ prompt }),
                    credentials: 'same-origin',
                });
                const result = await response.json();
                if (!response.ok || !result.ok) throw new Error(result.error || 'The assistant could not answer.');

                const turn = document.createElement('article');
                turn.dataset.assistantTurn = '';
                turn.style.cssText = 'padding-top:14px; border-top:1px solid #eef1f5;';
                const question = document.createElement('p');
                question.style.cssText = 'margin:0 0 8px; white-space:pre-wrap;';
                const questionLabel = document.createElement('strong');
                questionLabel.textContent = 'You';
                question.append(questionLabel, document.createElement('br'), document.createTextNode(prompt));
                const answer = document.createElement('p');
                answer.style.cssText = 'margin:0; white-space:pre-wrap; line-height:1.7;';
                answer.textContent = result.answer;
                const metadata = document.createElement('small');
                metadata.style.cssText = 'display:block; margin-top:7px; color:var(--muted);';
                metadata.textContent = `${result.mode.toUpperCase()} · ${new Date().toLocaleString()}`;
                turn.append(question, answer, metadata);
                conversation.append(turn);

                promptInput.value = '';
                promptInput.focus({ preventScroll: true });
                status.textContent = result.mode === 'mock' || result.mode === 'mock-fallback'
                    ? 'Answered from your visible task data.'
                    : 'Answer received.';
            } catch (error) {
                status.textContent = error.message;
                promptInput.focus({ preventScroll: true });
            } finally {
                submitButton.disabled = false;
                submitLabel.textContent = 'Ask assistant';
            }
        });
    }
});
