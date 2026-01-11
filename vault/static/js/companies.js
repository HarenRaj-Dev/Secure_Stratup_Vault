document.addEventListener('DOMContentLoaded', () => {
    const navLinks = document.querySelectorAll('.company-navbar a');
    
    // Logic to highlight active tab based on URL
    const currentPath = window.location.pathname;
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});

function confirmDeleteCompany() {
    return confirm("Are you sure? This will permanently delete all encrypted files associated with this company.");
}

function addNewUser(button) {
    const companyId = button.getAttribute('data-company-id');
    window.location.href = '/companies/' + companyId + '/add_user';
}