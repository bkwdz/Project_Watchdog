require('dotenv').config();
const app = require('./app');
const { waitForDatabase } = require('./db');
const { migrate } = require('./db/migrate');
const { resumeQueuedScans } = require('./services/scanWorker');

const PORT = process.env.PORT || 8080;

async function start() {
  try {
    await waitForDatabase();
    await migrate();
    await resumeQueuedScans();
    console.log('Database connection OK');

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Unable to start server:', err);
    process.exit(1);
  }
}

start();
