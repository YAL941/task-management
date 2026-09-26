document.addEventListener('DOMContentLoaded', () => {
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
    }

    document.querySelectorAll('[data-confirm]').forEach((form) => {
        form.addEventListener('submit', (event) => {
            if (!window.confirm(form.dataset.confirm)) event.preventDefault();
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
