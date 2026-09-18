pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template AgeCheck() {
    signal input dob;
    signal input salt;
    
    signal input currentDate;
    signal input minAgeThreshold;
    signal input commitment;

    signal output isVerified;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== dob;
    hasher.inputs[1] <== salt;
    hasher.out === commitment;

    component greaterEq = GreaterEqThan(32);
    greaterEq.in[0] <== currentDate - dob;
    greaterEq.in[1] <== minAgeThreshold;
    
    greaterEq.out === 1;

    isVerified <== 1;
}

component main {public [currentDate, minAgeThreshold, commitment]} = AgeCheck();