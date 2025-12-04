module.exports = (sequelize, DataTypes) => {
  const ScanResult = sequelize.define('ScanResult', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    deviceId: { type: DataTypes.INTEGER },
    raw: { type: DataTypes.JSON },
    summary: { type: DataTypes.STRING },
    severity: { type: DataTypes.STRING }
  }, {
    timestamps: true
  });

  return ScanResult;
};
