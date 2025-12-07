FROM osrf/ros:humble-desktop
RUN apt update && apt install -y build-essential curl pkg-config libssl-dev protobuf-compiler clang wget ros-humble-rmw-cyclonedds-cpp
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json


FROM chef AS builder

WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

ENTRYPOINT [ "tail" ]
