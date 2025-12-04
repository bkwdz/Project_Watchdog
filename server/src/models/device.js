module.exports = (sequelize, DataTypes) => {
  const Device = sequelize.define('Device', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING },
    ip: { type: DataTypes.STRING, allowNull: false, unique: true },
    mac: { type: DataTypes.STRING },
    vendor: { type: DataTypes.STRING },
    lastSeen: { type: DataTypes.DATE },
    meta: { type: DataTypes.JSON }
  }, {
    timestamps: true
  });

  return Device;
};
