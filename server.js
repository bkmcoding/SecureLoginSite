// app.js
const express = require('express');
const path = require('path');
const app = express();

const port = 3000;
const secureRoutes = require('./routes/secure.js');
const { initializeUserCache } = require('./utils/userData.js');


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use('/secure', secureRoutes);

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});


// Start the server
(async () => {
    await initializeUserCache();

    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
})();