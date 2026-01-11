function toggleAuth() {
    const subtitle = document.getElementById('auth-subtitle');
    const toggleMsg = document.getElementById('toggle-msg');
    const authForm = document.querySelector('form');
    const title = document.querySelector('.auth-header h2');

    if (title.innerText === "SECURE STARTUP VAULT") {
        title.innerText = "CREATE ACCOUNT";
        subtitle.innerText = "Join the most secure vault for your startup.";
        toggleMsg.innerHTML = 'Already have an account? <a href="javascript:void(0)" onclick="toggleAuth()">Login</a>';
        
        // Change form action to register
        authForm.action = "/register";
    } else {
        location.reload(); // Returns to default Login state
    }
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    // Find the span that was clicked
    const btn = event.target; 
    
    if (input.type === "password") {
        input.type = "text";
        btn.innerText = "HIDE";
    } else {
        input.type = "password";
        btn.innerText = "SHOW";
    }
}