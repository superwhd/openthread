//
// Created by handaw on 7/15/21.
//

#ifndef OT_POSIX_PLATFORM_INGRESS_FILTERING_HPP_
#define OT_POSIX_PLATFORM_INGRESS_FILTERING_HPP_

#include "common/logging.hpp"
#include "openthread/thread.h"

namespace ot {
namespace Posix {

otError InitOtbrForwardChain();

otError UpdateRules(otInstance *aInstance, const char *aThreadInterface);

} // namespace Posix
} // namespace ot

#endif // OT_POSIX_PLATFORM_INGRESS_FILTERING_HPP_
