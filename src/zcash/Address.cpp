#include "Address.hpp"
#include "NoteEncryption.hpp"
#include "hash.h"
#include "prf.h"
#include "streams.h"

#include <librustzcash.h>


const uint32_t SAPLING_BRANCH_ID = 0x76b809bb;

namespace libzcash {

  //Spending Keys
  std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const SproutSpendingKey &sk) const {
      return std::make_pair("z-sprout", sk.address());
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const SaplingExtendedSpendingKey &sk) const {
      return std::make_pair("z-sapling", sk.DefaultAddress());
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const OrchardExtendedSpendingKeyPirate &extsk) const {
      auto addressOpt = extsk.sk.GetDefaultAddress();
      if (addressOpt == std::nullopt) {
          throw std::invalid_argument("Cannot derive default address from invalid spending key");
      }
      return std::make_pair("z-orchard", addressOpt.value());
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const InvalidEncoding&) const {
      throw std::invalid_argument("Cannot derive default address from invalid spending key");
  }

  //Diversifid SpendingKeys
  std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedSpendingKey::operator()(const SaplingDiversifiedExtendedSpendingKey &dsk) const {
      SaplingPaymentAddress addr = dsk.extsk.ToXFVK().fvk.in_viewing_key().address(dsk.d).value();
      return std::make_pair("z-sapling", addr);
  }
    std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedSpendingKey::operator()(const OrchardDiversifiedExtendedSpendingKeyPirate &dsk) const {
        auto fvkOpt = dsk.extsk.sk.GetFVK();
        if (fvkOpt == std::nullopt) {
            throw std::invalid_argument("Cannot derive default address from invalid diversified spending key");
        }
        auto addressOpt = fvkOpt.value().GetAddress(dsk.d);
        if (addressOpt == std::nullopt) {
            throw std::invalid_argument("Cannot derive default address from invalid diversified spending key");
        }
        return std::make_pair("z-orchard", addressOpt.value());
    }
  std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedSpendingKey::operator()(const InvalidEncoding&) const {
      throw std::invalid_argument("Cannot derive default address from invalid spending key");
  }

  //Viewing Keys
  std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const SproutViewingKey &sk) const {
      return std::make_pair("z-sprout", sk.address());
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const SaplingExtendedFullViewingKey &sk) const {
      return std::make_pair("z-sapling", sk.DefaultAddress());
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const OrchardExtendedFullViewingKeyPirate &sk) const {
      auto address = sk.fvk.GetDefaultAddress();
      if (address == std::nullopt) {
          throw std::invalid_argument("Cannot derive default address from invalid viewing key");
      }
      return std::make_pair("z-orchard", address.value());
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const InvalidEncoding&) const {
      throw std::invalid_argument("Cannot derive default address from invalid viewing key");
  }

  //Diversified Viewing Keys
  std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedViewingKey::operator()(const SaplingDiversifiedExtendedFullViewingKey &dvk) const {
      SaplingPaymentAddress addr = dvk.extfvk.fvk.in_viewing_key().address(dvk.d).value();
      return std::make_pair("z-sapling", addr);
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedViewingKey::operator()(const OrchardDiversifiedExtendedFullViewingKeyPirate &dvk) const {
      auto addr = dvk.extfvk.fvk.GetAddress(dvk.d);
      if (addr == std::nullopt) {
          throw std::invalid_argument("Cannot derive default address from invalid diversified full viewing key");
      }
      return std::make_pair("z-orchard", addr.value());
  }
  std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedViewingKey::operator()(const InvalidEncoding&) const {
      throw std::invalid_argument("Cannot derive address from invalid viewing key");
  }

}

class IsValidAddressForNetwork : public boost::static_visitor<bool> {
    public:

        bool operator()(const libzcash::SproutPaymentAddress &addr) const {
            return false;
        }

        bool operator()(const libzcash::SaplingPaymentAddress &addr) const {
            return true;
        }

        bool operator()(const libzcash::OrchardPaymentAddressPirate &addr) const {
            return true;
        }

        bool operator()(const libzcash::InvalidEncoding &addr) const {
            return false;
        }
};

bool IsValidPaymentAddress(const libzcash::PaymentAddress& zaddr) {
    return std::visit(IsValidAddressForNetwork(), zaddr);
}

bool IsValidViewingKey(const libzcash::ViewingKey& vk) {
    return vk.index() != 0;
}

bool IsValidDiversifiedViewingKey(const libzcash::DiversifiedViewingKey& vk) {
    return vk.index() != 0;
}

bool IsValidSpendingKey(const libzcash::SpendingKey& zkey) {
    return zkey.index() != 0;
}

bool IsValidDiversifiedSpendingKey(const libzcash::DiversifiedSpendingKey& zkey) {
    return zkey.index() != 0;
}
