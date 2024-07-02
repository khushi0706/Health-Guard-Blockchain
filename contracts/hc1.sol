// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;
pragma experimental ABIEncoderV2;

contract Healthcare {
    struct Patient {
        string name;
        uint age;
        string gender;
        string condition;
        string contactNumber;
        string medicalHistory;
    }

    mapping(address => Patient) public patients;

    event PatientRegistered(
        address indexed patientAddress,
        string name,
        uint age,
        string gender,
        string condition,
        string contactNumber,
        string medicalHistory
    );

    function addPatient(
        string memory _name,
        uint _age,
        string memory _gender,
        string memory _condition,
        string memory _contactNumber,
        string memory _medicalHistory
    ) public {
        require(bytes(patients[msg.sender].name).length == 0, "Patient record already exists");

        patients[msg.sender] = Patient({
            name: _name,
            age: _age,
            gender: _gender,
            condition: _condition,
            contactNumber: _contactNumber,
            medicalHistory: _medicalHistory
        });

        emit PatientRegistered(msg.sender, _name, _age, _gender, _condition, _contactNumber, _medicalHistory);
    }
}

