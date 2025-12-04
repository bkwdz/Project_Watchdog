const { sequelize } = require('../models');

async function run() {
  try {
    await sequelize.authenticate();
    console.log('DB OK, syncing...');
    await sequelize.sync({ alter: true });
    console.log('Sync complete');
    process.exit(0);
  } catch (err) {
    console.error('Migration error', err);
    process.exit(1);
  }
}

run();
