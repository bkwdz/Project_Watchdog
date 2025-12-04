require('dotenv').config();

const isSqlite = !!process.env.SQLITE_STORAGE && !process.env.DATABASE_URL;

module.exports = {
  development: isSqlite
    ? {
        dialect: 'sqlite',
        storage: process.env.SQLITE_STORAGE || './database.sqlite'
      }
    : {
        url: process.env.DATABASE_URL,
        dialect: 'postgres'
      }
};
