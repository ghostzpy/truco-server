const { DataTypes } = require('sequelize');
const sequelize = require('./database'); // Adjust the path as necessary

const ResetToken = sequelize.define('ResetToken', {
  token: {
    type: DataTypes.STRING,
    allowNull: false
  },
  expireAt: {
    type: DataTypes.DATE,
    allowNull: false
  },
  userId: {
    type: DataTypes.INTEGER,
    references: {
      model: 'Users',
      key: 'id',
    }
  }
}, {
  timestamps: false  // This disables the automatic timestamps
});

module.exports = ResetToken;