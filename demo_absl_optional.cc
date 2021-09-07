#include <absl/types/optional.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>

class RecordRdata {
 public:
  virtual ~RecordRdata() {}

  // Return true if `data` represents RDATA in the wire format with a valid size
  // for the give `type`. Always returns true for unrecognized `type`s as the
  // size is never known to be invalid.
  static bool HasValidSize(const std::string& data, uint16_t type);

  virtual bool IsEqual(const RecordRdata* other) const = 0;
  virtual uint16_t Type() const = 0;
};

class OptRecordRdata {
 public:
  class Opt {
   public:
    static constexpr size_t kHeaderSize = 4;  // sizeof(code) + sizeof(size)

    Opt(uint16_t code, std::string data) {}

    bool operator==(const Opt& other) const {return false;}

    uint16_t code() const { return code_; }
    std::string data() const { return data_; }

   private:
    uint16_t code_;
    std::string data_;
  };

  static const uint16_t kType = 0;

  OptRecordRdata() {}
  OptRecordRdata(OptRecordRdata&& other) {}
  // ~OptRecordRdata() override {}
  ~OptRecordRdata() {}

  OptRecordRdata& operator=(const OptRecordRdata&& other) { return *this; }

  static std::unique_ptr<OptRecordRdata> Create(const std::string& data) {
    return nullptr; 
  }
  // bool IsEqual(const RecordRdata* other) const override { return false; }
  bool IsEqual(const RecordRdata* other) const { return false; }
  // uint16_t Type() const override { return 0; }
  uint16_t Type() const { return 0; }

  const std::vector<char>& buf() const { return buf_; }

  const std::vector<Opt>& opts() const { return opts_; }
  void AddOpt(const Opt& opt) {}

  // Add all Opts from |other| to |this|.
  void AddOpts(const OptRecordRdata& other) {}

  bool ContainsOptCode(uint16_t opt_code) const { return false; }

 private:
  std::vector<Opt> opts_;
  std::vector<char> buf_;

  // OptRecordRdata(const OptRecordRdata&) = delete;
  // OptRecordRdata& operator=(const OptRecordRdata&) = delete;
};

absl::optional<OptRecordRdata> foo() {
  OptRecordRdata b;
  return b;
}

int main() {
  auto rv = foo();
  std::cout << rv.has_value() << std::endl;
  return 0;
}