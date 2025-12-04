const { Device } = require('../models');

exports.list = async (req, res, next) => {
  try {
    const devices = await Device.findAll();
    res.json(devices);
  } catch (err) { next(err); }
};

exports.create = async (req, res, next) => {
  try {
    const d = await Device.create(req.body);
    res.status(201).json(d);
  } catch (err) { next(err); }
};

exports.get = async (req, res, next) => {
  try {
    const d = await Device.findByPk(req.params.id);
    if (!d) return res.status(404).json({ error: 'Not found' });
    res.json(d);
  } catch (err) { next(err); }
};

exports.update = async (req, res, next) => {
  try {
    const d = await Device.findByPk(req.params.id);
    if (!d) return res.status(404).json({ error: 'Not found' });
    await d.update(req.body);
    res.json(d);
  } catch (err) { next(err); }
};

exports.remove = async (req, res, next) => {
  try {
    const d = await Device.findByPk(req.params.id);
    if (!d) return res.status(404).json({ error: 'Not found' });
    await d.destroy();
    res.status(204).end();
  } catch (err) { next(err); }
};
