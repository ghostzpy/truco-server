const { DataTypes } = require('sequelize');
const sequelize = require('./database'); // Certifique-se que o caminho está correto

const User = sequelize.define('User', {
    name: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    points: {
        type: DataTypes.INTEGER,
        defaultValue: 100
    },
    balance: {
        type: DataTypes.INTEGER,
        defaultValue: 0
    },
    isAdmin: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    verificationToken: {
        type: DataTypes.STRING,
        allowNull: true // Definido como true para permitir que este campo seja nulo após a verificação
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: false // O padrão é false, significa que o usuário precisa verificar o e-mail para ativar a conta
    }
});

module.exports = User;