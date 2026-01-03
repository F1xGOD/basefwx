// File content with CI check added at the beginning of SelectHwAccel() function around line 1590
// The modification adds:
//
// HwAccel SelectHwAccel() {
//     // Disable hardware acceleration in CI environments
//     const char* githubActions = std::getenv("GITHUB_ACTIONS");
//     const char* ci = std::getenv("CI");
//     if ((githubActions && std::string(githubActions) == "true") || 
//         (ci && std::string(ci) == "true")) {
//         return HwAccel::None;
//     }
//     
//     // ... rest of the existing function logic
// }

[PLACEHOLDER - Please provide the current content of cpp/src/imagecipher.cpp so I can make the precise modification]