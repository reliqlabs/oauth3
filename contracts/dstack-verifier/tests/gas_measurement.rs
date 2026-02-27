use cosmwasm_std::{Binary, Empty, Response};
use cosmwasm_vm::testing::{
    instantiate, execute, mock_env, mock_info, mock_instance_with_gas_limit,
};
use dstack_verifier_contract::msg::{InstantiateMsg, ExecuteMsg};

static WASM: &[u8] = include_bytes!(
    "../artifacts/dstack_verifier_contract.wasm"
);

const GAS_LIMIT: u64 = 100_000_000_000_000; // 100T internal gas units

#[test]
fn measure_verify_quote_gas() {
    let mut deps = mock_instance_with_gas_limit(WASM, GAS_LIMIT);

    // Instantiate
    let init_msg = InstantiateMsg {
        admin: None,
        expected_config: None,
    };
    let info = mock_info("creator", &[]);
    let mut env = mock_env();
    // Set realistic timestamp (Feb 2025) for collateral validation
    env.block.time = cosmwasm_std::Timestamp::from_seconds(1772137255); // current time

    let gas_before_init = deps.get_gas_left();
    let _res: Response<Empty> =
        instantiate(&mut deps, env.clone(), info.clone(), init_msg).unwrap();
    let gas_after_init = deps.get_gas_left();
    let init_gas = gas_before_init - gas_after_init;
    eprintln!("Instantiate gas (internal): {}", init_gas);
    eprintln!("Instantiate gas (SDK ~÷140): {}", init_gas / 140);

    // Load test fixtures
    let quote_hex = include_str!("fixtures/quote.hex");
    let quote_bytes = hex::decode(quote_hex.trim()).expect("decode quote hex");
    let collateral_json = include_bytes!("fixtures/collateral.json");

    let exec_msg = ExecuteMsg::VerifyQuote {
        quote: Binary::from(quote_bytes),
        collateral: Binary::from(collateral_json.to_vec()),
    };

    let info = mock_info("verifier", &[]);
    let gas_before = deps.get_gas_left();
    let result: cosmwasm_std::ContractResult<Response<Empty>> =
        execute(&mut deps, env.clone(), info, exec_msg);
    let gas_after = deps.get_gas_left();
    let verify_gas = gas_before - gas_after;

    eprintln!("\n=== VERIFY QUOTE GAS MEASUREMENT ===");
    eprintln!("Internal gas used: {}", verify_gas);
    eprintln!("SDK gas (~÷140):   {}", verify_gas / 140);
    eprintln!("Result: {:?}", result);
    eprintln!("====================================");
}
