const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

async function initDB() {
  return open({
    filename: './dev.sqlite',
    driver: sqlite3.Database
  });
}

module.exports = initDB();
