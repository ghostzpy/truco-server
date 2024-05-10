const { DataTypes } = require('sequelize');
const sequelize = require('./database'); // Verifique se o caminho está correto

const Notification = sequelize.define('notifications', {
  title: {
      type: DataTypes.STRING,
      allowNull: false
  },
  description: {
      type: DataTypes.TEXT,
      allowNull: false
  },
  dateCreated: {
      type: DataTypes.DATE,
      allowNull: false
  },
  expiredDate: {
      type: DataTypes.DATE,
      allowNull: true
  },
  user: {
      type: DataTypes.STRING,
      allowNull: false
  },
  type: {
      type: DataTypes.ENUM('normal', 'alert', 'blue', 'red'),
      allowNull: false
  }
}, {
  // Desabilita os campos de timestamp automático
  timestamps: false
});

module.exports = Notification;