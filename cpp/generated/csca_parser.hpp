// This file was autogenerated by some hot garbage in the `uniffi-bindgen-react-native` crate.
// Trust me, you don't want to mess with it!
#pragma once
#include <jsi/jsi.h>
#include <iostream>
#include <map>
#include <memory>
#include <ReactCommon/CallInvoker.h>
#include "UniffiCallInvoker.h"

namespace react = facebook::react;
namespace jsi = facebook::jsi;

class NativeCscaParser : public jsi::HostObject {
  private:
    // For calling back into JS from Rust.
    std::shared_ptr<uniffi_runtime::UniffiCallInvoker> callInvoker;

  protected:
    std::map<std::string,jsi::Value> props;
    jsi::Value cpp_uniffi_internal_fn_func_ffi__string_to_byte_length(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_internal_fn_func_ffi__string_to_arraybuffer(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_internal_fn_func_ffi__arraybuffer_to_string(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_fn_func_build_cert_tree_and_gen_proof(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_fn_func_build_cert_tree_root(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_fn_func_find_master_certificate(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_fn_func_parse_ldif(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_fn_func_parse_ldif_string(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_fn_func_parse_pem(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_fn_func_parse_pem_string(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_checksum_func_build_cert_tree_and_gen_proof(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_checksum_func_build_cert_tree_root(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_checksum_func_find_master_certificate(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_checksum_func_parse_ldif(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_checksum_func_parse_ldif_string(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_checksum_func_parse_pem(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_uniffi_csca_parser_checksum_func_parse_pem_string(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);
    jsi::Value cpp_ffi_csca_parser_uniffi_contract_version(jsi::Runtime& rt, const jsi::Value& thisVal, const jsi::Value* args, size_t count);

  public:
    NativeCscaParser(jsi::Runtime &rt, std::shared_ptr<uniffi_runtime::UniffiCallInvoker> callInvoker);
    virtual ~NativeCscaParser();

    /**
     * The entry point into the crate.
     *
     * React Native must call `NativeCscaParser.registerModule(rt, callInvoker)` before using
     * the Javascript interface.
     */
    static void registerModule(jsi::Runtime &rt, std::shared_ptr<react::CallInvoker> callInvoker);

    /**
     * Some cleanup into the crate goes here.
     *
     * Current implementation is empty, however, this is not guaranteed to always be the case.
     *
     * Clients should call `NativeCscaParser.unregisterModule(rt)` after final use where possible.
     */
    static void unregisterModule(jsi::Runtime &rt);

    virtual jsi::Value get(jsi::Runtime& rt, const jsi::PropNameID& name);
    virtual void set(jsi::Runtime& rt,const jsi::PropNameID& name,const jsi::Value& value);
    virtual std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt);
};