use byteorder::{ByteOrder, BigEndian, ReadBytesExt};
use bstr::{ByteSlice};

const PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH:usize = 100;
const UINT64_TYPE_LENGTH:usize = 8;
const CONSENSUS_STATE_LENGTH_BYTES_LENGTH:usize = 32;

const CHAIN_ID_LENGTH:usize = 32;
const HEIGHT_LENGTH:usize = 8;
const VALIDATOR_SET_HASH_LENGTH:usize = 32;
const APP_HASH_LENGTH:usize = 32;
const VALIDATOR_PUBKEY_LENGTH:usize = 32;
const VALIDATOR_VOTING_POWER_LENGTH:usize = 8;
const MAX_CONSENSUS_STATE_LENGTH:usize = 32 * (128 - 1);

struct Validator {
    pub_key: Vec<u8>,
    voting_power: u64,
}

struct ConsensusState {
    chain_id: String,
    height: u64,
    app_hash: Vec<u8>,
    cur_validator_set_hash: Vec<u8>,
    next_validator_set: Vec<Validator>,
}

impl ConsensusState  {
    pub fn encode(self) -> Result<Vec<u8>, string> {
        let validator_set_size:usize = self.next_validator_set.len();

        let serialize_length:usize = CHAIN_ID_LENGTH + HEIGHT_LENGTH + APP_HASH_LENGTH + VALIDATOR_SET_HASH_LENGTH + validator_set_size*(VALIDATOR_PUBKEY_LENGTH+VALIDATOR_VOTING_POWER_LENGTH);
        if serialize_length > MAX_CONSENSUS_STATE_LENGTH {
            Err(format!("too many validators {}, consensus state bytes should not exceed {}", self.next_validator_set.len(), MAX_CONSENSUS_STATE_LENGTH))
        }

        let mut encoded_bytes:Vec<u8> = Vec::new();
        if self.chain_id.len() > CHAIN_ID_LENGTH {
            Err("chainID length should be no more than 32")
        }

        let mut chain_id_bytes:[u8;CHAIN_ID_LENGTH] = [0;CHAIN_ID_LENGTH];
        chain_id_bytes[..self.chain_id.len()].copy_from_slice(self.chain_id.as_bytes());
        encoded_bytes.extend(chain_id_bytes.to_vec());

        let mut height_bytes:[u8;HEIGHT_LENGTH] = [0;HEIGHT_LENGTH];
        BigEndian::write_u64(&mut height_bytes[..], self.height);
        encoded_bytes.extend(height_bytes.to_vec());

        encoded_bytes.extend(self.app_hash);

        encoded_bytes.extend(self.cur_validator_set_hash);

        for index in 0..validator_set_size {
            let mut validator_bytes: [u8; VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH] = [0; VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH];

            validator_bytes[..VALIDATOR_PUBKEY_LENGTH].copy_from_slice(self.next_validator_set[index].pub_key.as_slice());
            let mut voting_power_bytes:[u8;VALIDATOR_VOTING_POWER_LENGTH] = [0;VALIDATOR_VOTING_POWER_LENGTH];
            BigEndian::write_u64(&mut voting_power_bytes[..], self.next_validator_set[index].voting_power);

            validator_bytes[VALIDATOR_PUBKEY_LENGTH..].copy_from_slice(&voting_power_bytes[..]);
            encoded_bytes.extend(validator_bytes.to_vec());
        }

        Ok(encoded_bytes)
    }
}


struct TmHeaderValidate {
}


impl TmHeaderValidate {
    pub fn run(input: &[u8]) -> Result<Vec<u8>, string> {
        let input_length: usize = input.len() ;
        if input_length <= PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH {
            Err("invalid input")
        }

        let payload_length:u64 = BigEndian::read_u64(&input[PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH-UINT64_TYPE_LENGTH..PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH]);
        if input_length  != payload_length as usize + PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH {
            Err(format!("invalid input: input size should be {}, actual the size is {}", payload_length+PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH as u64, input_length))
        }

        let mut encoded_bytes:Vec<u8> = Vec::new();

        Ok(encoded_bytes)
    }

    fn decode_tendermint_header_validation_input(input: &[u8]) {
        let cs_len:u64 =  BigEndian::read_u64(&input[CONSENSUS_STATE_LENGTH_BYTES_LENGTH-UINT64_TYPE_LENGTH..CONSENSUS_STATE_LENGTH_BYTES_LENGTH]);
        let input_length: usize = input.len();
        if input_length <= CONSENSUS_STATE_LENGTH_BYTES_LENGTH + cs_len as usize {
            panic!("invalid consensus length")
        }
        // TODO:
    }

    fn decode_consensus_state(input: &[u8]) -> Result<ConsensusState, string> {
        let minimum_length:usize = CHAIN_ID_LENGTH + HEIGHT_LENGTH + APP_HASH_LENGTH + VALIDATOR_SET_HASH_LENGTH;
        let single_validator_bytes_length:usize = VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH;
        let input_length: usize = input.len();

        if input_length <= minimum_length || (input_length - minimum_length)%single_validator_bytes_length != 0 {
            Err(format!("expected input size {}+{}*N, actual input size: {}", minimum_length, single_validator_bytes_length, input_length))
        }

        let mut pos:usize = 0;
        let chain_id = input[pos..pos+CHAIN_ID_LENGTH].trim_with(|c| c == '\x00');
        let chain_id_str = String::from_utf8_lossy(chain_id);
        pos = pos + CHAIN_ID_LENGTH;

        let height:u64 = BigEndian::read_u64(&input[pos..pos+HEIGHT_LENGTH]);
        pos = pos + HEIGHT_LENGTH;

        let mut app_hash:[u8; APP_HASH_LENGTH] = [0;APP_HASH_LENGTH];
        app_hash.copy_from_slice(&input[pos..pos + APP_HASH_LENGTH]);
        pos = pos + APP_HASH_LENGTH;

        let mut cur_validator_set_hash:[u8;VALIDATOR_SET_HASH_LENGTH] = [0;VALIDATOR_SET_HASH_LENGTH];
        cur_validator_set_hash.copy_from_slice(&input[pos..pos + VALIDATOR_SET_HASH_LENGTH]);

        let next_validator_set_size:usize = (input_length - minimum_length)/single_validator_bytes_length;

        let mut next_validator_set:Vec<Validator> = Vec::new();
        for index in 0..next_validator_set_size {
            let mut start_pos:usize = pos + index * single_validator_bytes_length;

            let mut pub_key_bytes:[u8; VALIDATOR_PUBKEY_LENGTH] = [0;VALIDATOR_PUBKEY_LENGTH];
            pub_key_bytes.copy_from_slice(&input[start_pos..start_pos + VALIDATOR_PUBKEY_LENGTH]);
            start_pos = start_pos + VALIDATOR_PUBKEY_LENGTH;

            let voting_power:u64 = BigEndian::read_u64(&input[start_pos..start_pos+VALIDATOR_VOTING_POWER_LENGTH]);

            let validator = Validator{
                pub_key: pub_key_bytes.to_vec(),
                voting_power,
            };
            next_validator_set.push(validator);
        }

        let consensus_state = ConsensusState{
            chain_id: chain_id_str.to_string(),
            height,
            app_hash: app_hash.to_vec(),
            cur_validator_set_hash: cur_validator_set_hash.to_vec(),
            next_validator_set,
        };
        Ok(consensus_state)
    }
}
