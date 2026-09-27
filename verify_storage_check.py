from io import BytesIO
from werkzeug.datastructures import FileStorage
from main import MAX_FILE_SIZE, validate_uploads

print('MAX_FILE_SIZE=', MAX_FILE_SIZE)
for label, filename, content_type, payload in [
    ('oversized', 'report.pdf', 'application/pdf', b'x' * (MAX_FILE_SIZE + 1)),
    ('invalid_ext', 'evil.php', 'application/x-php', b'<?php echo 1; ?>'),
]:
    file_obj = FileStorage(stream=BytesIO(payload), filename=filename, content_type=content_type)
    try:
        validate_uploads([file_obj])
        print(label, 'UNEXPECTED_PASS')
    except Exception as exc:
        print(label, type(exc).__name__, str(exc))
