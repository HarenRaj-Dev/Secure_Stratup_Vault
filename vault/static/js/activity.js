document.addEventListener('DOMContentLoaded', () => {
    const logSearch = document.getElementById('logSearch'); // Add this ID to an input in your HTML
    const logTable = document.querySelector('.vault-table tbody');

    if (logSearch) {
        logSearch.addEventListener('keyup', function() {
            const query = this.value.toLowerCase();
            const rows = logTable.querySelectorAll('tr');

            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        });
    }
});