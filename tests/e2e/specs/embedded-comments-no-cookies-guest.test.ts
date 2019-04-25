/// <reference path="../test-types.ts"/>

import * as _ from 'lodash';
import assert = require('assert');
import fs = require('fs');
import server = require('../utils/server');
import utils = require('../utils/utils');
import pages = require('../utils/pages');
import pagesFor = require('../utils/pages-for');
import settings = require('../utils/settings');
import make = require('../utils/make');
import logAndDie = require('../utils/log-and-die');
import c = require('../test-constants');

declare let browser: any;

let everyonesBrowsers;
let maria;
let mariasBrowser;
let guestsBrowser;

let idAddress: IdAddress;
let siteId: any;

const mariasCommentOnePageAaa = 'mariasCommentOnePageAaa';
const guestCommentOne = 'guestCommentOne';
const guestCommentTwo = 'guestCommentTwo';

const localHostname = 'comments-for-e2e-test-embdb3c-localhost-8080';
const embeddingOrigin = 'http://e2e-test-embdb3c.localhost:8080';
const pageAaaSlug = 'emb-cmts-b3c-aaa.html';


describe("emb cmts no cookies   TyT295KBF6301", () => {

  it("initialize people", () => {
    everyonesBrowsers = _.assign(browser, pagesFor(browser));
    mariasBrowser = everyonesBrowsers;
    guestsBrowser = everyonesBrowsers;
    maria = make.memberMaria();
  });

  it("import a site", () => {
    const site: SiteData = make.forumOwnedByOwen('embdb3c', { title: "Emb Cmts No Cookeis" });
    site.meta.localHostname = localHostname;
    site.settings.allowEmbeddingFrom = embeddingOrigin;
    site.settings.allowGuestLogin = true;
    site.settings.requireVerifiedEmail = false;
    site.settings.mayComposeBeforeSignup = true;
    site.settings.mayPostBeforeEmailVerified = true;
    idAddress = server.importSiteData(site);
    siteId = idAddress.id;
  });

  it("create an embedding page b3c-aaa", () => {
    const dir = 'target';
    fs.writeFileSync(`${dir}/${pageAaaSlug}`, makeHtml('b3c-aaa', '#500'));
    function makeHtml(pageName: string, bgColor: string): string {
      return utils.makeEmbeddedCommentsHtml({ pageName, discussionId: '', localHostname, bgColor});
    }
  });

  it("Maria opens embedding page aaa", () => {
    mariasBrowser.go(embeddingOrigin + '/' + pageAaaSlug);
  });

  it("She submits a reply", () => {
    mariasBrowser.switchToEmbeddedCommentsIrame();
    mariasBrowser.topic.clickReplyToEmbeddingBlogPost();
    mariasBrowser.switchToEmbeddedEditorIrame();
    mariasBrowser.editor.editText(mariasCommentOnePageAaa);
    mariasBrowser.editor.save();
  });

  it("... needs to sign up, when submiting the reply", () => {
    mariasBrowser.swithToOtherTabOrWindow();
    mariasBrowser.loginDialog.createPasswordAccount(
        maria, false, 'THERE_WILL_BE_NO_VERIFY_EMAIL_DIALOG');
    mariasBrowser.switchBackToFirstTabOrWindow();
  });

  it("Her reply appears", () => {
    mariasBrowser.switchToEmbeddedCommentsIrame();
    mariasBrowser.topic.waitForPostNrVisible(c.FirstReplyNr);
    mariasBrowser.topic.assertPostTextMatches(c.FirstReplyNr, mariasCommentOnePageAaa);
  });

  it("After page refresh, she's logged out", () => {
    mariasBrowser.refresh();
    mariasBrowser.complex.waitForNotLoggedInInEmbeddedCommentsIframe();
  });

  it("A guest, Graeddelina, appears and clicks Reply", () => {
    guestsBrowser.switchToEmbeddedCommentsIrame();
    guestsBrowser.topic.clickReplyToPostNr(c.FirstReplyNr);
    guestsBrowser.switchToEmbeddedEditorIrame();
    guestsBrowser.editor.editText(guestCommentOne);
    guestsBrowser.editor.save();
  });

  it("... logs in as guest, when submitting", () => {
    guestsBrowser.swithToOtherTabOrWindow();
    guestsBrowser.disableRateLimits();
    guestsBrowser.loginDialog.signUpLogInAs_Real_Guest("Graeddelina Guest");
    guestsBrowser.switchBackToFirstTabOrWindow();
  });

  it("... the reply appears", () => {
    guestsBrowser.switchToEmbeddedCommentsIrame();
    guestsBrowser.topic.waitForPostNrVisible(c.FirstReplyNr + 1);
    guestsBrowser.topic.assertPostTextMatches(c.FirstReplyNr + 1, guestCommentOne);
  });

  it("After page refresh, she's logged out, because no cookies", () => {
    guestsBrowser.refresh();
    guestsBrowser.complex.waitForNotLoggedInInEmbeddedCommentsIframe();
  });

  it("Graeddelina starts typing a 2nd comment", () => {
    guestsBrowser.switchToEmbeddedCommentsIrame();
    guestsBrowser.topic.clickReplyToPostNr(c.FirstReplyNr);
    guestsBrowser.switchToEmbeddedEditorIrame();
    guestsBrowser.editor.editText(guestCommentTwo);
    guestsBrowser.editor.save();
  });

  it("... she has to log in as guest again", () => {
    guestsBrowser.swithToOtherTabOrWindow();
    guestsBrowser.disableRateLimits();
    guestsBrowser.loginDialog.signUpLogInAs_Real_Guest("Graeddelina Forever");
    guestsBrowser.switchBackToFirstTabOrWindow();
  });

  it("... her 2nd comment appears", () => {
    guestsBrowser.switchToEmbeddedCommentsIrame();
    guestsBrowser.topic.waitForPostNrVisible(c.FirstReplyNr + 2);
    guestsBrowser.topic.assertPostTextMatches(c.FirstReplyNr + 2, guestCommentTwo);
  });

});

