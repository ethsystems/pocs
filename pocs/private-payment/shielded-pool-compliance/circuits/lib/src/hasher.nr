use poseidon::poseidon::bn254;

pub fn hash_1(input: [Field; 1]) -> Field {
    bn254::hash_1(input)
}

pub fn hash_2(input: [Field; 2]) -> Field {
    bn254::hash_2(input)
}

pub fn hash_3(input: [Field; 3]) -> Field {
    bn254::hash_3(input)
}

pub fn hash_4(input: [Field; 4]) -> Field {
    bn254::hash_4(input)
}

pub fn hash_5(input: [Field; 5]) -> Field {
    bn254::hash_5(input)
}

pub fn hash_merkle_node(l: Field, r: Field) -> Field {
    hash_2([l, r])
}

#[test]
fn test_hash_1_known_answer() {
    assert(
        hash_1([1])
            == 18586133768512220936620570745912940619677854269274689475585506675881198879027,
    );
}

#[test]
fn test_hash_2_known_answer() {
    assert(
        hash_2([1, 2])
            == 7853200120776062878684798364095072458815029376092732009249414926327459813530,
    );
}

#[test]
fn test_hash_3_known_answer() {
    assert(
        hash_3([1, 2, 3])
            == 6542985608222806190361240322586112750744169038454362455181422643027100751666,
    );
}

#[test]
fn test_hash_4_known_answer() {
    assert(
        hash_4([1, 2, 3, 4])
            == 18821383157269793795438455681495246036402687001665670618754263018637548127333,
    );
}

#[test]
fn test_hash_5_known_answer() {
    assert(
        hash_5([1, 2, 3, 4, 5])
            == 6183221330272524995739186171720101788151706631170188140075976616310159254464,
    );
}
