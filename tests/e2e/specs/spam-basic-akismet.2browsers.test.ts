/// <reference path="../test-types.ts"/>

import * as _ from 'lodash';
import assert = require('assert');
import server = require('../utils/server');
import utils = require('../utils/utils');
import pagesFor = require('../utils/pages-for');
import settings = require('../utils/settings');
import make = require('../utils/make');
import logAndDie = require('../utils/log-and-die');
import c = require('../test-constants');

declare let browser: any;
declare let browserA: any;
declare let browserB: any;

let everyone;
let owen;
let owensBrowser;
let maria;
let mariasBrowser;
let mallory;
let mallorysBrowser;
let mons;
let monsBrowser;
let guest;
let guestsBrowser;
let strangersBrowser;

let idAddress: IdAddress;
let forumTitle = "Basic Spam Test Forum";
let topicTitle = "Links links links";
let post2Selector = '#post-2';
let post3Selector = '#post-3';

const AkismetAlwaysSpamName = 'viagra-test-123';
const AkismetAlwaysSpamEmail = 'akismet-guaranteed-spam@example.com';

describe("spam test, external services like Akismet and Google Safe Browsing  TyTSPEXT", () => {

  if (!settings.include3rdPartyDependentTests) {
    console.log("Skipping this spec; no 3rd party credentials specified.");
    return;
  }

  it("initialize people", () => {
    everyone = _.assign(browser, pagesFor(browser));
    owen = make.memberOwenOwner();
    owensBrowser = _.assign(browserA, pagesFor(browserA));
    mons = make.memberModeratorMons();
    maria = make.memberMaria();
    mallory = make.memberMallory();
    guest = make.guestGunnar();
    // Reuse the same browser.
    monsBrowser = _.assign(browserB, pagesFor(browserB));
    mariasBrowser = monsBrowser;
    mallorysBrowser = monsBrowser;
    guestsBrowser = monsBrowser;
    strangersBrowser = monsBrowser;
  });

  it("import a site", () => {
    let site: SiteData = make.forumOwnedByOwen('basicspam', { title: forumTitle });
    site.settings.allowGuestLogin = true;
    site.settings.requireVerifiedEmail = false;
    site.members.push(mons);
    site.members.push(maria);
    //site.members.push(mallory);
    idAddress = server.importSiteData(site);
settings.debugEachStep=true;
  });

  it("Mallory tries to sign up with a spammers address", () => {
    mallorysBrowser.go(idAddress.origin);
    mallorysBrowser.debug();
    mallorysBrowser.complex.signUpAsMemberViaTopbar(
        { ...mallory, emailAddress: AkismetAlwaysSpamEmail });
  });

  it("... he's rejected, because of the email address", () => {
    mallorysBrowser.debug();
    // EdE7KVF2_
  });

  it("Mallory retries with a non-spam address", () => {
    mallorysBrowser.debug();
    mallorysBrowser.complex.signUpAsMemberViaTopbar(mallory);
    mallorysBrowser.disableRateLimits();
  });

  it("Mallory submits spam", () => {
    mallorysBrowser.debug();

    mallorysBrowser.forumButtons.clickCreateTopic();
    mallorysBrowser.editor.editTitle(topicTitle);
    mallorysBrowser.editor.editText(`${AkismetAlwaysSpamName}
        http://www.example.com/link-10`);
    mallorysBrowser.editor.save();
    mallorysBrowser.editor.debug();
    //mallorysBrowser.serverErrorDialog.waitAndAssertTextMatches(/links.*EdE4KFY2_/);
    mallorysBrowser.serverErrorDialog.close();
  });

  it("Mallory posts a topic with a few links only, that's OK", () => {
    mallorysBrowser.editor.editText(`Not many links :-(
        http://www.example.com/link-1
        http://www.example.com/link-2`);
    mallorysBrowser.rememberCurrentUrl();
    mallorysBrowser.editor.save();
    mallorysBrowser.waitForNewUrl();
    mallorysBrowser.assertPageTitleMatches(topicTitle);
  });

  it("... then a *spam* comment", () => {
    mallorysBrowser.complex.replyToOrigPost('__ed_spam' + '_test_123__');
  });

  it("... which will be visible, initially", () => {
    mallorysBrowser.waitForVisible(post2Selector);
  });

  it("... then he posts a *not* spam comment", () => {
    mallorysBrowser.complex.replyToOrigPost("Not spam. Ham.");
  });

  it("The spam comment gets hidden, eventually", () => {
    // [E2EBUG] failed x 2:
    //    "FAIL: Error: unexpected alert open: {Alert text : You were writing something?}"
    mallorysBrowser.topic.refreshUntilBodyHidden(2);
  });

  it("... but the not-spam comment is still visible", () => {
    mallorysBrowser.topic.assertPostNotHidden(3);
  });

  it("... and remains visible", () => {
    mallorysBrowser.pause(2000); // later: server.waitUntilSpamCheckQueueEmpty()
    assert(mallorysBrowser.isVisible('#post-3'));
  });

  it("Mallory logs out", () => {
    mallorysBrowser.topbar.clickLogout();
  });

  it("A stranger attempts to sign up with password + a spammer's email: fills in details,", () => {
    strangersBrowser.topbar.clickSignUp();
    strangersBrowser.loginDialog.fillInUsername("stranger");
    strangersBrowser.loginDialog.fillInEmail('__ed_spam' + '_test_123__@ex.co');
    strangersBrowser.loginDialog.fillInPassword("public1234");
  });

  // todo: ip addr link

  it("... clicks submit", () => {
    strangersBrowser.loginDialog.clickSubmit();
  });

  it("... accepts terms", () => {
    strangersBrowser.loginDialog.acceptTerms();
  });

  it("... but is rejected", () => {
    mallorysBrowser.serverErrorDialog.waitAndAssertTextMatches(/spam.*EdE7KVF2_/);
  });

  it("... closes the error dialog", () => {
    mallorysBrowser.serverErrorDialog.close();
    strangersBrowser.loginDialog.clickCancel();
  });

  it("Owen goes to the Review admin tab and logs in", () => {
    owensBrowser.adminArea.goToReview(idAddress.origin);
    owensBrowser.loginDialog.loginWithPassword(owen);
  });

});

