const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('u787971721_apptrucoarena', 'u787971721_apptrucoarena', 'A&=ivIC&*>5n', {
    host: 'srv1197.hstgr.io',
    dialect: 'mysql',
    logging: false,
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
});

module.exports = sequelize;