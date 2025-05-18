// Dashboard.js - Additional functionality for the honeypot dashboard

// Add timestamp to prevent caching
function getTimestampedUrl(url) {
    return url + (url.includes('?') ? '&' : '?') + '_t=' + new Date().getTime();
}

// Global variables to store attempt data
let webAttempts = [];
let sshAttempts = [];
let allAttempts = [];

// Fetch web login attempts
function fetchWebLoginAttempts() {
    fetch(getTimestampedUrl('/api/honeypot/web-login-attempts'))
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Store the data globally
            webAttempts = data;
            
            const tableBody = document.getElementById('web-login-attempts-body');
            if (!tableBody) return; // Guard clause if element doesn't exist
            
            tableBody.innerHTML = '';
            
            if (data.length === 0) {
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 4;
                cell.textContent = 'No web login attempts recorded';
                cell.style.textAlign = 'center';
                row.appendChild(cell);
                tableBody.appendChild(row);
                return;
            }
            
            data.forEach(attempt => {
                const row = document.createElement('tr');
                
                const timeCell = document.createElement('td');
                // Format the timestamp to be more readable
                const timestamp = new Date(attempt.timestamp);
                timeCell.textContent = timestamp.toLocaleString();
                
                const ipCell = document.createElement('td');
                ipCell.textContent = attempt.ip;
                
                const usernameCell = document.createElement('td');
                usernameCell.textContent = attempt.username || '-';
                
                const passwordCell = document.createElement('td');
                passwordCell.textContent = attempt.password || '-';
                
                row.appendChild(timeCell);
                row.appendChild(ipCell);
                row.appendChild(usernameCell);
                row.appendChild(passwordCell);
                
                tableBody.appendChild(row);
            });
            
            // Update attempt statistics
            updateAttemptStats();
        })
        .catch(error => {
            console.error('Error fetching web login attempts:', error);
            const tableBody = document.getElementById('web-login-attempts-body');
            if (tableBody) {
                tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: red;">Error loading data</td></tr>';
            }
        });
}

// Fetch SSH login attempts
function fetchSSHLoginAttempts() {
    fetch(getTimestampedUrl('/api/honeypot/ssh-login-attempts'))
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            const tableBody = document.getElementById('ssh-login-attempts-body');
            if (!tableBody) return; // Guard clause if element doesn't exist
            
            tableBody.innerHTML = '';
            
            if (data.length === 0) {
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 4;
                cell.textContent = 'No SSH login attempts recorded';
                cell.style.textAlign = 'center';
                row.appendChild(cell);
                tableBody.appendChild(row);
                return;
            }
            
            data.forEach(attempt => {
                const row = document.createElement('tr');
                
                const timeCell = document.createElement('td');
                timeCell.textContent = attempt.timestamp;
                
                const ipCell = document.createElement('td');
                ipCell.textContent = attempt.ip;
                
                const usernameCell = document.createElement('td');
                usernameCell.textContent = attempt.username || '-';
                
                const passwordCell = document.createElement('td');
                passwordCell.textContent = attempt.password || '-';
                
                row.appendChild(timeCell);
                row.appendChild(ipCell);
                row.appendChild(usernameCell);
                row.appendChild(passwordCell);
                
                tableBody.appendChild(row);
            });
        })
        .catch(error => {
            console.error('Error fetching SSH login attempts:', error);
            const tableBody = document.getElementById('ssh-login-attempts-body');
            if (tableBody) {
                tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: red;">Error loading data</td></tr>';
            }
        });
}

// Fetch all attempts for statistics
function fetchAllAttempts() {
    fetch(getTimestampedUrl('/api/logs'))
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            allAttempts = data;
            updateAttemptStats();
        })
        .catch(error => {
            console.error('Error fetching all attempts:', error);
        });
}

// Update attempt statistics
function updateAttemptStats() {
    // Only proceed if we have the stats element and data
    const statsElement = document.getElementById('attempt-stats');
    if (!statsElement || !allAttempts.length) return;
    
    // Count attempts by type
    const typeCounts = {};
    allAttempts.forEach(attempt => {
        const type = attempt.type || 'access';
        typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    
    // Count unique IPs
    const uniqueIPs = new Set(allAttempts.map(attempt => attempt.ip)).size;
    
    // Get most common username and password
    const usernameCounts = {};
    const passwordCounts = {};
    
    allAttempts.forEach(attempt => {
        if (attempt.username) {
            usernameCounts[attempt.username] = (usernameCounts[attempt.username] || 0) + 1;
        }
        if (attempt.password) {
            passwordCounts[attempt.password] = (passwordCounts[attempt.password] || 0) + 1;
        }
    });
    
    const mostCommonUsername = Object.entries(usernameCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 1)
        .map(entry => `${entry[0]} (${entry[1]} attempts)`)[0] || 'None';
    
    const mostCommonPassword = Object.entries(passwordCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 1)
        .map(entry => `${entry[0]} (${entry[1]} attempts)`)[0] || 'None';
    
    // Update the stats display
    statsElement.innerHTML = `
        <p><strong>Total Attempts:</strong> ${allAttempts.length}</p>
        <p><strong>Unique IPs:</strong> ${uniqueIPs}</p>
        <p><strong>Web Login Attempts:</strong> ${typeCounts['login_attempt'] || 0}</p>
        <p><strong>SSH Login Attempts:</strong> ${typeCounts['ssh_login_attempt'] || 0}</p>
        <p><strong>Most Common Username:</strong> ${mostCommonUsername}</p>
        <p><strong>Most Common Password:</strong> ${mostCommonPassword}</p>
    `;
}

function checkHoneypotStatus() {
    // Update timestamp
    const lastUpdatedElement = document.getElementById('last-updated');
    if (lastUpdatedElement) {
        lastUpdatedElement.textContent = new Date().toLocaleTimeString();
    }
    
    // Refresh login attempt data
    fetchWebLoginAttempts();
    fetchSSHLoginAttempts();
    fetchAllAttempts();
}

document.addEventListener('DOMContentLoaded', function() {
    // Check if honeypot is active and update data
    function checkHoneypotStatus() {
        // Update timestamp
        const lastUpdatedElement = document.getElementById('last-updated');
        if (lastUpdatedElement) {
            lastUpdatedElement.textContent = new Date().toLocaleTimeString();
        }
        
        // Refresh login attempt data
        fetchWebLoginAttempts();
        fetchSSHLoginAttempts();
    }
    
    // Initialize dashboard components
    function initDashboard() {
        // Set up any additional dashboard functionality here
        console.log("Dashboard initialized");
        
        // Check status immediately
        checkHoneypotStatus();
        
        // Then check every 10 seconds
        setInterval(checkHoneypotStatus, 10000);
    }
    
    // Initialize the dashboard
    initDashboard();
    
    // Add a manual refresh button functionality if it doesn't exist
    const refreshButton = document.getElementById('refresh-data');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            fetchWebLoginAttempts();
            fetchSSHLoginAttempts();
        });
    }
});

// This fetch is not needed as the dashboard.html already has its own fetch functions
// The element "recent-logs" doesn't exist in your HTML
/*
fetch("/api/logs")
    .then(response => response.json())
    .then(logs => {
        const recentLogs = document.getElementById("recent-logs");
        logs.slice(-5).forEach(log => { // Show last 5 logs
            const li = document.createElement("li");
            li.textContent = `${log.timestamp} - ${log.ip}:${log.port} - ${log.data}`;
            recentLogs.appendChild(li);
        });
    })
    .catch(error => console.error("Error fetching logs:", error));
*/