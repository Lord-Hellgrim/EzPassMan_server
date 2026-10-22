package EzPassMan_Server

import "core:net"
import "core:fmt"
import "core:crypto/noise"
import "core:encoding/endian"

import noise_net"../common/noise_networking"
import ss "../common/smallstrings"
import crypto_core "../common/ezpassman_crypto_core"
import sqlite "../common/sqlite3_bindings"
import client "../client"

EzString :: ss.SmallString(255)


parse_request :: proc(data: []u8) -> client.Request {
    user_id, succeeded := ss.from_slice(data[1 : 257], 255)
    auth_token, endian_success := endian.get_u64(data[257 : 257+8], .Little)
    kind: client.RequestType
    switch data[0] {
        case 1: kind = .NewUser
        case 2: kind = .FetchVault
        case 3: kind = .DeleteVault
        case 4: kind = .UpdateVault
        case: kind = .Error
    }
    request := client.Request{
        kind = kind,
        user_id = user_id,
        auth_token = auth_token,
    }

    return request
}

main :: proc() {

    vault_database, open_status := sqlite.open_database("vault_database.db")
    if open_status != .OK {
        panic("Failed to open database")
    }

    sqlite.execute_one_shot(vault_database, "DROP TABLE vaults")
    sqlite.execute_one_shot(vault_database, "CREATE TABLE vaults (user_id TEXT PRIMARY KEY, vault BLOB)")
    insert_test, _ := sqlite.prepare_statement(vault_database, "INSERT INTO vaults (user_id, vault) VALUES (\"test\", ?)")
    sqlite.step_statement(vault_database, insert_test)
    sqlite.finalize_statement(insert_test)

    new_user_stmt, _ := sqlite.prepare_statement(vault_database, "INSERT INTO vaults (user_id, vault) VALUES (?, ?)")
    read_stmt, _ := sqlite.prepare_statement(vault_database, "SELECT vault FROM vaults WHERE user_id = ?")
    update_stmt, _ := sqlite.prepare_statement(vault_database, "UPDATE vaults SET vault = ? WHERE user_id = ?")
    delete_stmt, _ := sqlite.prepare_statement(vault_database, "DELETE FROM vaults WHERE user_id = ?")

    fmt.println("Starting...")
    server_address, parsed := net.parse_endpoint("127.0.0.1:5000")
    fmt.println("Parsed endpoint...")
    if !parsed {
        panic("PARSING WRONG!!")
    }
    listener, listen_err := net.listen_tcp(server_address)
    fmt.println("Opened listener...")

    server_should_keep_running := true

    for server_should_keep_running {
        free_all(context.temp_allocator)
        socket, peer, status := net.accept_tcp(listener) // Blocks server until connection is available
        hs : noise.Handshake_State
        hs_status := noise.handshake_init(&hs, false, nil, nil, nil, noise_net.DEFAULT_PROTOCOL_NAME)
        connection, connection_status := noise_net.establish_connection_all_the_way(socket, peer)
        data, nonce, data_status := noise_net.receive_data(&connection, expected_len = size_of(client.Request))
        if data_status != .ok {
            fmt.println("Status: ", data_status)
            return
        }
        request := parse_request(data)

        switch request.kind {
            case .NewUser: {
                unvalidated_vault, nonce, new_user_status := noise_net.receive_data(
                    &connection, 
                    expected_len = size_of(EzString) + size_of(crypto_core.Vault), 
                    allocator = context.temp_allocator
                )
                if new_user_status != .ok {
                    continue
                }
                user_id_raw := unvalidated_vault[:size_of(EzString)]
                user_id, valid := ss.from_slice(user_id_raw, 255)
                if !valid {
                    continue
                }
                if crypto_core.blob_is_valid(unvalidated_vault) {
                    sqlite.bind_text(new_user_stmt, ss.as_string(&user_id), 0)
                    sqlite.bind_blob(new_user_stmt, unvalidated_vault, 1)
                    sqlite.step_statement(vault_database, new_user_stmt)
                    sqlite.reset_statement(new_user_stmt)
                } else {
                    continue
                }

            }
            case .FetchVault: {
                sqlite.bind_text(read_stmt, ss.as_string(&request.user_id), 0)
                read_step_status := sqlite.step_statement(vault_database, read_stmt)
                if read_step_status != .ROW {
                    continue
                }
                vault_blob, read_status := sqlite.get_column_blob(read_stmt, 0)
                
                noise_net.send_data(&connection, vault_blob, allocator = context.temp_allocator)
            }
            case .DeleteVault: {
                panic("NEW USER PATH UNIMPLEMENTED")
            }
            case .UpdateVault: {
                panic("NEW USER PATH UNIMPLEMENTED")
            }
            case .Error: {
                panic("NEW USER PATH UNIMPLEMENTED")
            }
        }
        
        // connection_status : noise_net.ConnectionStatus = .handshake_pending
        // connection : noise_net.Connection
        // for  {
        //     connection, connection_status = noise_net.establish_connection_step(&hs, socket, server_address)
        //     if connection_status == .handshake_pending {
        //         continue
        //     } else if connection_status == .handshake_complete {
        //         data, nonce, recv_status := noise_net.receive_data(&connection)
        //         fmt.println("Recv status: ", recv_status)
        //         fmt.println("NONCE: ", nonce)
        //         fmt.println(data)
                
        //         fmt.println("SUCCESS!!")
        //         break
        //     } else {
        //         fmt.println(connection_status)
        //         break
        //     }
        // }
    }
        
}