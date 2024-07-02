// 2_deploy_contract.js
const MyContract = artifacts.require("Healthcare");

module.exports = function (deployer) {
  deployer.deploy(MyContract);
};

