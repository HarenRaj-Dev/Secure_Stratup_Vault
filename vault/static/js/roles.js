// Add visual feedback when toggles are changed
const toggles = document.querySelectorAll('.switch input');

toggles.forEach(toggle => {
    toggle.addEventListener('change', function() {
        const parent = this.closest('.perm-item');
        if (this.checked) {
            parent.style.borderLeft = "4px solid var(--accent)";
        } else {
            parent.style.borderLeft = "4px solid transparent";
        }
    });
});

function deleteRolePrompt() {
    if(confirm("Delete this role? Users assigned to this role may lose access.")) {
        // Logic to trigger delete route
    }
}