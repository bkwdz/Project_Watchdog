const { Sequelize, DataTypes } = require('sequelize');
const cfg = require('../config/config')[process.env.NODE_ENV || 'development'];

let sequelize;
if (cfg.url) {
  sequelize = new Sequelize(cfg.url, { dialect: cfg.dialect, logging: false });
} else {
  sequelize = new Sequelize({ dialect: cfg.dialect, storage: cfg.storage, logging: false });
}

const db = {};
db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.Device = require('./device')(sequelize, DataTypes);
db.ScanResult = require('./scanResult')(sequelize, DataTypes);

db.Device.hasMany(db.ScanResult, { foreignKey: 'deviceId', onDelete: 'CASCADE' });
db.ScanResult.belongsTo(db.Device, { foreignKey: 'deviceId' });

db.User = require('./user')(sequelize, DataTypes);

module.exports = db;
