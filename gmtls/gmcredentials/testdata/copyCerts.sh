#!/bin/bash
src_dir=../../../x509/testdata
dist_dir=.

cp ${src_dir}/sm2_ca_cert.cer ${dist_dir}/ca.cert
cp ${src_dir}/sm2_enc_cert.cer ${dist_dir}/encrypt.cert
cp ${src_dir}/sm2_enc_key.pem ${dist_dir}/encrypt.key
cp ${src_dir}/sm2_sign_cert.cer ${dist_dir}/sign.cert
cp ${src_dir}/sm2_sign_key.pem ${dist_dir}/sign.key
cp ${src_dir}/sm2_auth_cert.cer ${dist_dir}/user.cert
cp ${src_dir}/sm2_auth_key.pem ${dist_dir}/user.key
