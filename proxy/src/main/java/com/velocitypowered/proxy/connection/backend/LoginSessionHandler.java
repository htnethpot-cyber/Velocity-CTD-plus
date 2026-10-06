/*
 * Copyright (C) 2018-2023 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.velocitypowered.proxy.connection.backend;

import com.velocitypowered.api.event.player.CookieRequestEvent;
import com.velocitypowered.api.event.player.ServerLoginPluginMessageEvent;
import com.velocitypowered.api.event.player.configuration.PlayerEnteredConfigurationEvent;
import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import com.velocitypowered.api.proxy.player.ClientWorldSwitches;
import com.velocitypowered.api.proxy.server.PlayerInfoForwarding;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.config.VelocityConfiguration;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.connection.MinecraftSessionHandler;
import com.velocitypowered.proxy.connection.PlayerDataForwarding;
import com.velocitypowered.proxy.connection.client.ClientPlaySessionHandler;
import com.velocitypowered.proxy.connection.client.ConnectedPlayer;
import com.velocitypowered.proxy.connection.util.ConnectionRequestResults;
import com.velocitypowered.proxy.connection.util.ConnectionRequestResults.Impl;
import com.velocitypowered.proxy.network.Connections;
import com.velocitypowered.proxy.network.netty.VelocityReadTimeoutHandler;
import com.velocitypowered.proxy.protocol.ProtocolUtils;
import com.velocitypowered.proxy.protocol.StateRegistry;
import com.velocitypowered.proxy.protocol.packet.ClientboundCookieRequestPacket;
import com.velocitypowered.proxy.protocol.packet.ClientboundStoreCookiePacket;
import com.velocitypowered.proxy.protocol.packet.DisconnectPacket;
import com.velocitypowered.proxy.protocol.packet.EncryptionRequestPacket;
import com.velocitypowered.proxy.protocol.packet.LoginAcknowledgedPacket;
import com.velocitypowered.proxy.protocol.packet.LoginPluginMessagePacket;
import com.velocitypowered.proxy.protocol.packet.LoginPluginResponsePacket;
import com.velocitypowered.proxy.protocol.packet.ServerLoginSuccessPacket;
import com.velocitypowered.proxy.protocol.packet.SetCompressionPacket;
import com.velocitypowered.proxy.util.except.QuietRuntimeException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.LogManager;

/**
 * Handles a player trying to log into the proxy.
 */
public class LoginSessionHandler implements MinecraftSessionHandler {

  static {
    LogManager.getLogger(LoginSessionHandler.class);
  }

  /**
   * Login-phase channel the backend companion plugin uses to ask for the client's entity ID, so a
   * world-preserving switch can reuse it. See {@code keep-client-world-on-switch}.
   */
  private static final String SEAMLESS_CHANNEL = "velocityctd:seamless";

  /**
   * Payload format version, so the plugin can refuse a proxy it does not understand.
   */
  private static final byte SEAMLESS_FORMAT_VERSION = 1;

  /**
   * Login-phase channel a backend plugin uses to ask how the arriving player authenticated. The
   * backend cannot tell on its own: behind a proxy it always runs in offline mode, so every player
   * looks the same to it whether or not they own the game.
   */
  private static final String ACCOUNT_TYPE_CHANNEL = "velocityctd:accounttype";

  /**
   * Payload format version for {@link #ACCOUNT_TYPE_CHANNEL}, independent of the seamless one so
   * either can change without disturbing the other.
   */
  private static final byte ACCOUNT_TYPE_FORMAT_VERSION = 1;

  /**
   * The player did not authenticate with Mojang: either this proxy runs in offline mode, or a
   * plugin waved them through. A "cracked" account, in the usual phrasing.
   */
  private static final byte ACCOUNT_TYPE_OFFLINE = 0;

  /**
   * The player authenticated with Mojang's session servers, so the account is real and the name
   * and UUID on it are theirs.
   */
  private static final byte ACCOUNT_TYPE_PREMIUM = 1;

  private static final Component MODERN_IP_FORWARDING_FAILURE =
      Component.translatable("velocity.error.modern-forwarding-failed");

  private final VelocityServer server;
  private final VelocityServerConnection serverConn;
  private final CompletableFuture<Impl> resultFuture;
  private boolean informationForwarded;

  LoginSessionHandler(VelocityServer server, VelocityServerConnection serverConn,
      CompletableFuture<Impl> resultFuture) {
    this.server = server;
    this.serverConn = serverConn;
    this.resultFuture = resultFuture;
  }

  @Override
  public boolean handle(EncryptionRequestPacket packet) {
    throw new IllegalStateException("Backend server is online-mode!");
  }

  @Override
  public boolean handle(LoginPluginMessagePacket packet) {
    MinecraftConnection mc = serverConn.ensureConnected();
    VelocityConfiguration configuration = server.getConfiguration();

    PlayerInfoForwarding forwardingMode = serverConn.getServer().getPlayerInfoForwardingMode();

    if (forwardingMode == PlayerInfoForwarding.MODERN
        && packet.getChannel().equals(PlayerDataForwarding.CHANNEL)) {

      int requestedForwardingVersion = PlayerDataForwarding.MODERN_DEFAULT;
      // Check version
      if (packet.content().readableBytes() == 1) {
        requestedForwardingVersion = packet.content().readByte();
      }
      ConnectedPlayer player = serverConn.getPlayer();
      ByteBuf forwardingData = PlayerDataForwarding.createForwardingData(
          configuration.getForwardingSecret(),
          serverConn.getPlayerRemoteAddressAsString(),
          player.getProtocolVersion(),
          player.getGameProfile(),
          player.getIdentifiedKey(),
          requestedForwardingVersion);

      LoginPluginResponsePacket response = new LoginPluginResponsePacket(
              packet.getId(), true, forwardingData);
      mc.write(response);
      informationForwarded = true;
    } else if (packet.getChannel().equals(SEAMLESS_CHANNEL)) {
      mc.write(new LoginPluginResponsePacket(packet.getId(), true, seamlessHandshake()));
    } else if (packet.getChannel().equals(ACCOUNT_TYPE_CHANNEL)) {
      mc.write(new LoginPluginResponsePacket(packet.getId(), true, accountTypeHandshake()));
    } else {
      // Don't understand, fire event if we have subscribers
      if (!this.server.getEventManager().hasSubscribers(ServerLoginPluginMessageEvent.class)) {
        mc.write(new LoginPluginResponsePacket(packet.getId(), false, Unpooled.EMPTY_BUFFER));
        return true;
      }

      final byte[] contents = ByteBufUtil.getBytes(packet.content());
      final MinecraftChannelIdentifier identifier = MinecraftChannelIdentifier
          .from(packet.getChannel());
      this.server.getEventManager().fire(new ServerLoginPluginMessageEvent(serverConn, identifier,
              contents, packet.getId()))
          .thenAcceptAsync(event -> {
            if (event.getResult().isAllowed()) {
              mc.write(new LoginPluginResponsePacket(packet.getId(), true, Unpooled
                  .wrappedBuffer(event.getResult().getResponse())));
            } else {
              mc.write(new LoginPluginResponsePacket(packet.getId(), false, Unpooled.EMPTY_BUFFER));
            }
          }, mc.eventLoop());
    }
    return true;
  }

  @Override
  public boolean handle(DisconnectPacket packet) {
    resultFuture.complete(ConnectionRequestResults.forDisconnect(packet, serverConn.getServer()));
    serverConn.disconnect();
    return true;
  }

  @Override
  public boolean handle(SetCompressionPacket packet) {
    serverConn.ensureConnected().setCompressionThreshold(packet.getThreshold());
    return true;
  }

  @Override
  public boolean handle(ServerLoginSuccessPacket packet) {
    PlayerInfoForwarding forwardingMode = serverConn.getServer().getPlayerInfoForwardingMode();

    if (forwardingMode == PlayerInfoForwarding.MODERN && !informationForwarded) {
      resultFuture.complete(ConnectionRequestResults.forDisconnect(MODERN_IP_FORWARDING_FAILURE, serverConn.getServer()));
      serverConn.disconnect();
      return true;
    }

    // The player has been logged on to the backend server, but we're not done yet. There could be
    // other problems that could arise before we get a JoinGame packet from the server.

    // Move into the PLAY phase.
    MinecraftConnection smc = serverConn.ensureConnected();

    // The backend has logged in, which is all the short login-timeout bounds. Configuration can
    // leave the backend silent for longer while the player catches up (known packs, a resource
    // pack hold), so the regular read-timeout applies from here on (issue GemstoneGG#938).
    if (smc.getChannel().pipeline().context(Connections.READ_TIMEOUT) != null) {
      smc.getChannel().pipeline().replace(Connections.READ_TIMEOUT, Connections.READ_TIMEOUT,
          new VelocityReadTimeoutHandler(server.getConfiguration().getReadTimeout(),
              TimeUnit.MILLISECONDS));
    }
    if (smc.getProtocolVersion().lessThan(ProtocolVersion.MINECRAFT_1_20_2)) {
      smc.setActiveSessionHandler(StateRegistry.PLAY, new TransitionSessionHandler(server, serverConn, resultFuture));
    } else {
      smc.write(new LoginAcknowledgedPacket());
      smc.setActiveSessionHandler(StateRegistry.CONFIG, new ConfigSessionHandler(server, serverConn, resultFuture));
      ConnectedPlayer player = serverConn.getPlayer();
      if (player.getClientSettingsPacket() != null) {
        smc.write(player.getClientSettingsPacket());
      }
      if (player.getConnection().getActiveSessionHandler() instanceof ClientPlaySessionHandler clientPlaySessionHandler) {
        // With "remove-reconfig" the client is left in play for the whole switch: this is the one
        // place that would otherwise push it back into configuration, and the "Reconfiguring..."
        // screen it shows. The backend still runs its own configuration phase; ConfigSessionHandler
        // answers it on the client's behalf.
        if (!server.getConfiguration().isRemoveReconfig()) {
          smc.setAutoReading(false);
          clientPlaySessionHandler.doSwitch().thenRunAsync(() -> smc.setAutoReading(true), smc.eventLoop());
        }
      } else {
        // Initial login - the player is already in configuration state.
        server.getEventManager().fireAndForget(new PlayerEnteredConfigurationEvent(player, serverConn));
      }
    }

    return true;
  }

  @Override
  public boolean handle(ClientboundStoreCookiePacket packet) {
    throw new IllegalStateException("Can only store cookie in CONFIGURATION or PLAY protocol");
  }

  @Override
  public boolean handle(ClientboundCookieRequestPacket packet) {
    server.getEventManager().fire(new CookieRequestEvent(serverConn.getPlayer(), packet.getKey()))
        .thenAcceptAsync(event -> {
          if (event.getResult().isAllowed()) {
            final Key resultedKey = event.getResult().getKey() == null
                ? event.getOriginalKey() : event.getResult().getKey();

            serverConn.getPlayer().getConnection().write(new ClientboundCookieRequestPacket(resultedKey));
          }
        }, serverConn.ensureConnected().eventLoop());

    return true;
  }

  @Override
  public void exception(Throwable throwable) {
    resultFuture.completeExceptionally(throwable);
  }

  @Override
  public void disconnected() {
    PlayerInfoForwarding forwardingMode = serverConn.getServer().getPlayerInfoForwardingMode();

    if (forwardingMode == PlayerInfoForwarding.LEGACY) {
      resultFuture.completeExceptionally(new QuietRuntimeException("""
              The connection to the remote server was unexpectedly closed.
              This is usually because the remote server does not have \
              BungeeCord IP forwarding correctly enabled.
              See https://docs.papermc.io/velocity/player-information-forwarding for instructions \
              on how to configure player info forwarding correctly."""));
    } else {
      resultFuture.completeExceptionally(
          new QuietRuntimeException("The connection to the remote server was unexpectedly closed.")
      );
    }
  }

  /**
   * Tells the backend companion plugin which entity ID this player's client already holds, so
   * the backend can reuse it instead of issuing a fresh one.
   *
   * <p>The backend cannot work this out for itself -- the ID was assigned by whichever server the
   * player joined first -- and it has to know before it builds the join game packet, which is why
   * this rides the login phase rather than an ordinary plugin message.</p>
   *
   * <p>A zero entity ID means "join the player normally": either the feature is off, or this is a
   * first join with no prior ID to preserve. The backend treats that as no instruction, and the
   * proxy's own check then falls back to a normal switch.</p>
   *
   * @return the response payload: a format byte followed by the entity ID
   */
  private ByteBuf seamlessHandshake() {
    final ConnectedPlayer player = serverConn.getPlayer();
    final int entityId = server.getConfiguration().isKeepClientWorldOnSwitch()
        ? ClientWorldSwitches.clientEntityId(player.getUniqueId())
        : 0;

    final ByteBuf response = Unpooled.buffer(5);
    response.writeByte(SEAMLESS_FORMAT_VERSION);
    ProtocolUtils.writeVarInt(response, entityId);
    return response;
  }

  /**
   * Tells a backend plugin how this player got in: with a real, Mojang-authenticated account, or
   * without one.
   *
   * <p>Only the proxy knows this. A backend behind a proxy runs in offline mode by definition --
   * it trusts whatever identity is forwarded to it -- so from where it stands a paid account and a
   * cracked one are indistinguishable. The answer rides the login phase so it is available before
   * the player joins, which is when anything that acts on it (restricting a rank, a shop, a
   * cosmetic tied to a real UUID) needs to have already decided.</p>
   *
   * <p>Bedrock players are deliberately not reported here. Geyser and Floodgate publish their own
   * API, and whichever side of the connection Floodgate is installed on can answer that question
   * accurately; a guess made here from UUID shape would be worse than the real thing.</p>
   *
   * @return the response payload: a format byte followed by the account type
   */
  private ByteBuf accountTypeHandshake() {
    final ByteBuf response = Unpooled.buffer(2);
    response.writeByte(ACCOUNT_TYPE_FORMAT_VERSION);
    response.writeByte(serverConn.getPlayer().isOnlineMode()
        ? ACCOUNT_TYPE_PREMIUM
        : ACCOUNT_TYPE_OFFLINE);
    return response;
  }
}
