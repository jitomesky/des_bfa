#!/bin/sh

gcc -std=c11 des_solver.c -lssl -lcrypto -fopenmp -o des_solver
./des_solver
