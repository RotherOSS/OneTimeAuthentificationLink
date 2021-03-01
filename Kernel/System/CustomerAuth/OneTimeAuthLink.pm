# --
# OTOBO is a web-based ticketing system for service organisations.
# --
# Copyright (C) 2001-2020 OTRS AG, https://otrs.com/
# Copyright (C) 2019-2021 Rother OSS GmbH, https://otobo.de/
# --
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# --

package Kernel::System::CustomerAuth::OneTimeAuthLink;

use strict;
use warnings;
use utf8;

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::CustomerUser',
    'Kernel::System::DB',
    'Kernel::System::Log',
);

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    # get database object
    $Self->{DBObject} = $Kernel::OM->Get('Kernel::System::DB');
    
    $Self->{Table} = 'ota_tokens';

    return $Self;
}

sub GetOption {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    if ( !$Param{What} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Need What!"
        );
        return;
    }

    # module options
    my %Option = (
        PreAuth => 0,
    );

    # return option
    return $Option{ $Param{What} };
}

sub ExtendedParamNames {
    my ( $Self, %Param ) = @_;
    
    return qw/OTAToken/;
}

sub Auth {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    if ( !$Param{OTAToken} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'debug',
            Message  => "No Token provided!"
        );
        return;
    }

    $Self->{DBObject}->Prepare(
        SQL => "SELECT used,user,ticket_number FROM $Self->{Table} WHERE token = ?",
        Bind => [ \$Param{OTAToken} ],
    );

    my @Row =  $Self->{DBObject}->FetchrowArray();
    my ( $Used, $User, $TicketNumber ) = ( 0 );

    if ( @Row ) {
        ( $Used, $User, $TicketNumber ) = @Row;
    }

    if ( !$Used || !$User ) {
        return {
            Error => $Kernel::OM->Get('Kernel::Config')->Get('OneTimeAuth::CustomerErrorMessageLinkExpired') || 'Ihr Link verweist auf kein noch gültiges Ticket.',
        }
    }

    my $CustomerUserObject = $Kernel::OM->Get('Kernel::System::CustomerUser');

    # send out new email if the ticket is still considered active but no current link exists
    if ( $Used == 1 ) {
        # store failed login count
        my %CustomerData = $CustomerUserObject->CustomerUserDataGet( User => $Param{User} );
        if (%CustomerData) {
            my $Count = $CustomerData{UserLoginFailed} || 0;
            $Count++;
            $CustomerUserObject->SetPreferences(
                Key    => 'UserLoginFailed',
                Value  => $Count,
                UserID => $CustomerData{UserLogin},
            );
        }

        # check whether active login link still exists
        $Self->{DBObject}->Prepare(
            SQL => "SELECT user FROM $Self->{Table} WHERE ticket_number = ? AND used = ?",
            Bind => [ \$TicketNumber, \2 ],
        );

        if ( $Self->{DBObject}->FetchrowArray() ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'debug',
                Message  => "CustomerUser '$User' tried to log in with an old token. New token exists - nothing to do."
            );

            return {
                Error => $Kernel::OM->Get('Kernel::Config')->Get('OneTimeAuth::CustomerErrorMessageWrongLink') || 'Aus Sicherheitsgründen müssen Sie den neuesten Ihnen zugesandten Link nutzen um auf dieses Ticket zuzugreifen.',
            }
        }
        else {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'debug',
                Message  => "CustomerUser '$User' tried to log in with an old token. No active token left - sending a new one via mail."
            );

            $Self->SendNewToken(
                User         => $User,
                TicketNumber => $TicketNumber,
            );

            return {
                Error => $Kernel::OM->Get('Kernel::Config')->Get('OneTimeAuth::CustomerErrorMessageNewLink') || 'Ihre Session ist leider abgelaufen - ein neuer Link wurde an Ihre Email-Adresse gesendet.',
            }
        }
    }
    elsif ( $Used == 2 ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'debug',
            Message  => "CustomerUser '$User' logged in via token."
        );

        $Self->DeactivateTicketTokens(
            TicketNumber => $TicketNumber,
        );

        return $User;
    }

    return;
}

sub GenerateToken {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/User TicketNumber/ ) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );
            return;
        }
    }

    # deactivate all other tokens for this ticket
    $Self->DeactivateTicketTokens(
        TicketNumber => $Param{TicketNumber},
    );

    my $OTATokenLength = 24;
    my $RandomString;

    my $Try = 1;
    while ( $Try ) {
        $RandomString = $Kernel::OM->Get('Kernel::System::Main')->GenerateRandomString(
            Length => $OTATokenLength,
        );

        # check whether the string already exists
        $Self->{DBObject}->Prepare(
            SQL => "SELECT user FROM $Self->{Table} WHERE token = ?",
            Bind => [ \$Param{OTAToken} ],
        );

        if ( $Self->{DBObject}->FetchrowArray() ) {
            $Try++;
        }
        else {
            $Try = 0;
        }

        if ( $Try > 5 ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Could not generate a unique random string after five retries - something is not right!"
            );
            return;
        }
    }

    return if !$Self->{DBObject}->Do(
        SQL => "INSERT INTO $Self->{Table} ( token, ticket_number, used, user, create_time, change_time )
            VALUES ( ?, ?, ?, ?, current_timestamp, current_timestamp )",
        Bind => [ \$RandomString, \$Param{TicketNumber}, \2, \$Param{User} ],
    );
    
    return $RandomString;
}

sub DeactivateTicketTokens {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/TicketNumber/ ) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );
            return;
        }
    }

    return if !$Self->{DBObject}->Do(
        SQL => "UPDATE $Self->{Table} SET used = 1, change_time = current_timestamp WHERE ticket_number = ? AND used = 2",
        Bind => [ \$Param{TicketNumber} ],
    );

    return 1;
}

sub DeleteTicketTokens {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/TicketNumber/ ) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );
            return;
        }
    }

    return if !$Self->{DBObject}->Do(
        SQL => "DELETE FROM $Self->{Table} WHERE ticket_number = ?",
        Bind => [ \$Param{TicketNumber} ],
    );

    return 1;
}

sub TicketLink {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    # check needed stuff
    for my $Needed ( qw/TicketNumber User/ ) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );

            return $ConfigObject->Get('OneTimeAuth::CustomerErrorMessageRefreshFailed') // 'Link could not be generated, please contact us directly!';
        }
    }

    my $TicketLink = $ConfigObject->Get('HttpType') . '://' . $ConfigObject->Get('FQDN') . '/otobo/customer.pl';
    $TicketLink .= "?Action=CustomerTicketZoom;TicketNumber=$Param{TicketNumber}";

    # check if the user already has a passsword - then no direct link is needed
    my %User = $Kernel::OM->Get('Kernel::System::CustomerUser')->CustomerUserDataGet(
        User => $Param{User},
    );

    unless ( $User{UserPassword} ) {
        # generate token
        my $Token = $Self->GenerateToken(
            %Param,
        );

        if ( !$Token ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Error in token generation!"
            );

            return $ConfigObject->Get('OneTimeAuth::CustomerErrorMessage') // 'Link could not be generated, please contact us directly!';
        }

        $TicketLink .= ";OTAToken=$Token";
    }

    return "<a href='$TicketLink' target='_blank'>$TicketLink</a>";
}

sub DeactivateClosedTickets {
    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $TicketObject = $Kernel::OM->Get('Kernel::System::Ticket');

    # get the compare time if a delay is given
    my $Delay       = $Kernel::OM->Get('Kernel::Config')->Get('OneTimeAuth::AccessDaysAfterClose') || 0;
    my $StillOKTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch() - 24*60*60*$Delay;

    $Self->{DBObject}->Prepare(
        SQL => "SELECT DISTINCT(ticket_number) FROM $Self->{Table}",
    );
    
    my @TicketNumbers;
    while ( my @Row = $Self->{DBObject}->FetchrowArray() ) {
        push @TicketNumbers, $Row[0];
    }
    
    TICKET:
    for my $TN ( @TicketNumbers ) {
        my $TicketID = $TicketObject->TicketIDLookup(
            TicketNumber => $TN,
        );

        my %Ticket = $TicketObject->TicketGet(
            TicketID => $TicketID,
        );

        # remove old tokens
        if ( $Ticket{StateType} eq 'closed' || $Ticket{StateType} eq 'removed' || $Ticket{StateType} eq 'merged' ) {
            if ( $Delay ) {
                my $LastChangedTime = $Kernel::OM->Create(
                    'Kernel::System::DateTime',
                    ObjectParams => {
                        String   => $Ticket{Changed},
                    }
                )->ToEpoch();

                next TICKET if $LastChangedTime > $StillOKTime;
            }

            $Self->DeleteTicketTokens(
                TicketNumber => $TN,
            ); 
        }
    }

    return 1;
}

sub SendNewToken {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    for my $Needed ( qw/TicketNumber User/ ) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!"
            );

            return;
        }
    }

    my $ConfigObject       = $Kernel::OM->Get('Kernel::Config');
    my $CustomerUserObject = $Kernel::OM->Get('Kernel::System::CustomerUser');
    my $TicketObject       = $Kernel::OM->Get('Kernel::System::Ticket');

    my $TicketID = $TicketObject->TicketIDLookup(
        TicketNumber => $Param{TicketNumber},
    );
    my %Ticket = $TicketObject->TicketGet(
        TicketID => $TicketID,
    );
    my %User = $Kernel::OM->Get('Kernel::System::CustomerUser')->CustomerUserDataGet(
        User => $Param{User},
    );

    my $TemplateGenerator = $Kernel::OM->Get('Kernel::System::TemplateGenerator');
    my $Sender            = $TemplateGenerator->Sender(
        QueueID => $Ticket{QueueID},
        UserID  => 1,
    );

    my $NotificationID = $ConfigObject->Get('OneTimeAuth::TokenRefreshNotificationID');

    my ( $Body, $Subject );

    if ( $NotificationID ) {
        my %Notification = $Kernel::OM->Get('Kernel::System::NotificationEvent')->NotificationGet(
            ID => $NotificationID,
        );

        my %Languages = map { $_ => $_ } @{ $Notification{Data}{LanguageID} };
        my $Language  = $Languages{de} || $Languages{en} || $Notification{Data}{LanguageID}[0];

        # replace place holder stuff
        $Body = $TemplateGenerator->_Replace(
            RichText        => $ConfigObject->Get('Frontend::RichText'),
            Text            => $Notification{Message}{$Language}{Body},
            Data            => {},
            TicketData      => \%Ticket,
            UserID          => 1,
        );

        $Subject = $TemplateGenerator->_Replace(
            RichText        => 0,
            Text            => $Notification{Message}{$Language}{Subject},
            Data            => {},
            TicketData      => \%Ticket,
            UserID          => 1,
        );
    }

    else {
        my $TicketLink = $Self->TicketLink( %Param );

        $Subject = "Neuer Authentifizierungslink für Ticket#$Ticket{TicketNumber}";
        $Body    = "Guten Tag<br/>Ihr aktueller Link um auf Ticket#$Ticket{TicketNumber} zugreifen zu können lautet:<br/>$TicketLink";
    }


    my $EmailObject = $Kernel::OM->Get('Kernel::System::Email');
    my $Sent = $EmailObject->Send(
        From     => $Sender,
        To       => $User{UserEmail},
        Subject  => $Subject,
        Charset  => 'utf-8',
        MimeType => 'text/html',
        Body     => $Body,
    );

    if ( !$Sent ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Could not send new token to $Param{User} for Ticket#$Param{TicketNumber}!"
        );

        return;
    }

    return 1;
}

1;
