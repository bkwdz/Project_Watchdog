require('dotenv').config();
const app = require('./app');
const { sequelize } = require('./models');

const PORT = process.env.PORT || 8080;

async function start() {
  try {
    await sequelize.authenticate();
    console.log('DB connection OK');

    // Sync DB (safe for dev). Remove or change in production.
    await sequelize.sync({ alter: true });

    if (process.env.ENABLE_SCHEDULER === 'true') {
      const { startScheduledJobs } = require('./utils/scheduler');
      startScheduledJobs();
    }

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Unable to start server:', err);
    process.exit(1);
  }
}

start();
