#pragma once

#include <csignal>

namespace basefwx::runtime {

inline volatile std::sig_atomic_t& StopFlag() noexcept {
    static volatile std::sig_atomic_t flag = 0;
    return flag;
}

inline void RequestStop() noexcept {
    StopFlag() = 1;
}

inline bool StopRequested() noexcept {
    return StopFlag() != 0;
}

inline void ResetStop() noexcept {
    StopFlag() = 0;
}

}  // namespace basefwx::runtime
