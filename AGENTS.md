# Auth Service Agents Guide

This service owns authentication and authorization flows.

## Scope

- user sign-in and sign-up flows
- JWT issuing and related auth state
- OAuth integrations
- auth-related mail, nickname, and identity bootstrap assets stored in this service

## Working Rules

- Treat token issuance, key handling, and auth flows as security-sensitive.
- Keep auth-specific behavior inside this service; expose integrations through API or messaging contracts.
- Review impact on `api-gateway` and downstream services when auth contracts change.
