function updateModelResults(modelData) {
    const {
        prediction,
        confidence,
        spam_probability,
        non_spam_probability,
        decision_score
    } = modelData;

    // Update main prediction
    const predictionText = prediction === 'spam' ? 'High Risk Token' : 'Safe Token';
    document.getElementById('model-prediction').textContent = predictionText;
    
    // Update confidence
    document.getElementById('model-confidence').textContent = confidence.charAt(0).toUpperCase() + confidence.slice(1);
    
    // Update probabilities
    const safeProb = (non_spam_probability * 100).toFixed(1);
    const riskProb = (spam_probability * 100).toFixed(1);
    
    document.getElementById('safe-probability').textContent = `${safeProb}%`;
    document.getElementById('risk-probability').textContent = `${riskProb}%`;
    
    document.getElementById('safe-prob-bar').style.width = `${safeProb}%`;
    document.getElementById('risk-prob-bar').style.width = `${riskProb}%`;
    
    // Update score
    const scoreElement = document.getElementById('model-score');
    scoreElement.classList.remove('spinner');
    
    // Calculate a score from 0-100 based on the decision score
    // Convert decision score to a 0-100 scale (adjust multiplier as needed)
    const normalizedScore = Math.round(50 + (decision_score * 25));
    const clampedScore = Math.max(0, Math.min(100, normalizedScore));
    
    scoreElement.textContent = clampedScore;
    
    // Add color class based on score
    if (clampedScore >= 70) {
        scoreElement.classList.add('score-high');
    } else if (clampedScore >= 40) {
        scoreElement.classList.add('score-medium');
    } else {
        scoreElement.classList.add('score-low');
    }
}