require('dotenv').config();
const { waitForDatabase } = require('../db');
const { migrate } = require('../db/migrate');

async function run() {
  try {
    await waitForDatabase();
    await migrate();
    console.log('Schema migration complete');
    process.exit(0);
  } catch (err) {
    console.error('Migration error', err);
    process.exit(1);
  }
}

run();
