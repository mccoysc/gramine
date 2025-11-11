const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.static(__dirname));
app.use('/lib', express.static(path.join(__dirname, '..')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'web', 'index.html'));
});

app.get('/examples.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'web', 'examples.html'));
});

app.listen(PORT, () => {
    console.log(`Test server running at http://localhost:${PORT}`);
    console.log(`Main test page: http://localhost:${PORT}`);
    console.log(`Examples page: http://localhost:${PORT}/examples.html`);
});
