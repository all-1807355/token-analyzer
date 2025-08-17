document.getElementById('search-form').addEventListener('submit', function(e) {
    e.preventDefault();
    const token = document.getElementById('token-input').value.trim();
    const chain = document.getElementById('chain-selector').value;
    
    if (!token) {
        alert('Please enter a token address');
        return;
    }

    window.location.href = `/results?token=${encodeURIComponent(token)}&chain=${encodeURIComponent(chain)}`;
});