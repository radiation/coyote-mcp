from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, ForeignKey, String, Table, Uuid, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# Deliberately no implicit authorization: membership is a discovery filter only.
collection_servers = Table(
    "collection_servers",
    Base.metadata,
    Column("collection_id", Uuid(as_uuid=True), ForeignKey("collections.id"), primary_key=True),
    Column("server_id", Uuid(as_uuid=True), ForeignKey("servers.id"), primary_key=True),
)


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    endpoint: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    tools: Mapped[list[Tool]] = relationship(back_populates="server")


class Tool(Base):
    __tablename__ = "tools"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    server_id: Mapped[UUID] = mapped_column(ForeignKey("servers.id"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(4096), default="")
    server: Mapped[Server] = relationship(back_populates="tools")


class Collection(Base):
    __tablename__ = "collections"

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(160), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    servers: Mapped[list[Server]] = relationship(secondary=collection_servers)
