FROM ubuntu:20.04

# General arguments
ARG INSTALL_ZSH="true"
ARG UPGRADE_PACKAGES="true"

# Non-root user arguments
ARG USERNAME=code
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Rust & Cargo arguments
ARG RUSTUP_HOME=/usr/local/rustup
ARG CARGO_HOME=/usr/local/cargo
ARG RUST_VERSION=1.48.0
ENV PATH=/usr/local/cargo/bin:$PATH

# Copy all general scripts
COPY scripts/*.sh /tmp/scripts/

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    # Install common packages, non-root user
    && bash /tmp/scripts/common.sh "$INSTALL_ZSH" "$USERNAME" "$USER_UID" "$USER_GID" "$UPGRADE_PACKAGES" \
    # Install rust toolchain & cargo
    && bash /tmp/scripts/rust.sh "$CARGO_HOME" "$RUSTUP_HOME" "$USERNAME" "true" "true" \
    # Clean up
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* /root/.gnupg /tmp/scripts

CMD ["sleep", "infinity"]