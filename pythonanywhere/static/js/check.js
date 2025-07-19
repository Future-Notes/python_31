// settings.js - Frontend utility for application settings
const settingCache = new Map();

window.check = async (key, defaultValue) => {
    // Return cached value if available
    if (settingCache.has(key)) {
        return settingCache.get(key);
    }

    try {
        const response = await fetch('/api/setting', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ key, default: defaultValue })
        });

        if (!response.ok) throw new Error('Failed to fetch setting');
        
        const data = await response.json();
        settingCache.set(key, data.value);  // Cache result
        return data.value;
    } catch (error) {
        console.error('Error fetching setting:', error);
        // Return default value if network fails
        return defaultValue;
    }
};