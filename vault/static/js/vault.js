// Feature 6: Anti-Screenshot & Privacy
document.addEventListener('keyup', (e) => {
    if (e.key === 'PrintScreen' || e.keyCode === 44) {
        navigator.clipboard.writeText('Screenshot Blocked');
        alert('Screenshots are disabled for security in Secure Startup Vault.');
    }
});

// Blur content when the user leaves the tab
window.addEventListener('blur', () => {
    document.body.style.filter = "blur(15px)";
});

window.addEventListener('focus', () => {
    document.body.style.filter = "none";
});

// File Upload Trigger
const uploadBtn = document.querySelector('.btn-primary');
const fileInput = document.getElementById('file-upload');

if(fileInput) {
    fileInput.onchange = () => {
        const fileName = fileInput.files[0].name;
        if(confirm(`Do you want to encrypt and secure "${fileName}"?`)) {
            fileInput.form.submit();
        }
    };
}