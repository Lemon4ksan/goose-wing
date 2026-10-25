// Client profile definitions and user-agent dispatch.
namespace wing;

import std;

// ---- client profiles -------------------------------------------------------

enum Profile {
    Wing,      // Authentic Wing Zero-Heap Systems Engine identity (Default)
    Custom,    // User-controlled custom profile
    None,      // Minimal raw client without default headers
}

// ---- profile user-agents ---------------------------------------------------

fn profile_user_agent(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing/1.0 (Goose Zero-Heap Systems Engine) NetStack/7.0",
        Custom => "Wing/1.0 (Custom Profile)",
        None => "goose-wing/0.1",
        _ => "Wing/1.0",
    };
}

fn profile_name(profile: Profile) -> const u8[:] {
    return match profile {
        Wing => "Wing",
        Custom => "Custom",
        None => "None",
        _ => "Wing",
    };
}
