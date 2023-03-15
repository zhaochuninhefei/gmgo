#!/bin/bash
src_dir=../../../x509/testdata
dist_dir=.

cp ${src_dir}/sm2_ca_cert.cer ${dist_dir}/sm2_ca.cert
cp ${src_dir}/sm2_sign_cert.cer ${dist_dir}/sm2_sign.cert
cp ${src_dir}/sm2_sign_key.pem ${dist_dir}/sm2_sign.key
cp ${src_dir}/sm2_auth_cert.cer ${dist_dir}/sm2_user.cert
cp ${src_dir}/sm2_auth_key.pem ${dist_dir}/sm2_user.key

cp ${src_dir}/ecdsa_ca_cert.cer ${dist_dir}/ecdsa_ca.cert
cp ${src_dir}/ecdsa_sign_cert.cer ${dist_dir}/ecdsa_sign.cert
cp ${src_dir}/ecdsa_sign_key.pem ${dist_dir}/ecdsa_sign.key
cp ${src_dir}/ecdsa_auth_cert.cer ${dist_dir}/ecdsa_user.cert
cp ${src_dir}/ecdsa_auth_key.pem ${dist_dir}/ecdsa_user.key

cp ${src_dir}/ecdsaext_ca_cert.cer ${dist_dir}/ecdsaext_ca.cert
cp ${src_dir}/ecdsaext_sign_cert.cer ${dist_dir}/ecdsaext_sign.cert
cp ${src_dir}/ecdsaext_sign_key.pem ${dist_dir}/ecdsaext_sign.key
cp ${src_dir}/ecdsaext_auth_cert.cer ${dist_dir}/ecdsaext_user.cert
cp ${src_dir}/ecdsaext_auth_key.pem ${dist_dir}/ecdsaext_user.key
