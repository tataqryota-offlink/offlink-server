const bcrypt = require('bcrypt');
bcrypt.hash('offlink@admin2026', 10).then(h => console.log(h));